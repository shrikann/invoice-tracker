package com.shri.invoicetracker.auth;

import com.shri.invoicetracker.business.Business;
import com.shri.invoicetracker.business.BusinessRepository;
import com.shri.invoicetracker.security.JwtService;
import com.shri.invoicetracker.user.AppUser;
import com.shri.invoicetracker.user.Role;
import com.shri.invoicetracker.user.UserRepository;
import io.jsonwebtoken.io.Encoders;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final String SECRET = Encoders.BASE64.encode(
            "unit-test-secret-that-is-at-least-32-bytes-long".getBytes(StandardCharsets.UTF_8));

    private final UserRepository userRepository = mock(UserRepository.class);
    private final BusinessRepository businessRepository = mock(BusinessRepository.class);
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final JwtService jwtService = new JwtService(SECRET, 30);
    private final LoginAttemptService loginAttemptService = new LoginAttemptService();
    private final AuthService authService = new AuthService(
            userRepository, businessRepository, passwordEncoder, jwtService, loginAttemptService);

    private AppUser storedUser(boolean enabled) {
        AppUser user = new AppUser();
        ReflectionTestUtils.setField(user, "id", 5L);
        user.setEmail("owner@example.com");
        user.setPasswordHash(passwordEncoder.encode("password123"));
        user.setRole(Role.OWNER);
        user.setEnabled(enabled);
        return user;
    }

    private void failLogin() {
        assertThatThrownBy(() -> authService.login(new LoginRequest("owner@example.com", "wrong-password")))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void registerCreatesBusinessAndOwnerAndReturnsAWorkingToken() {
        when(businessRepository.save(any(Business.class))).thenAnswer(invocation -> {
            Business business = invocation.getArgument(0);
            ReflectionTestUtils.setField(business, "id", 10L);
            return business;
        });
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> {
            AppUser user = invocation.getArgument(0);
            ReflectionTestUtils.setField(user, "id", 20L);
            return user;
        });

        AuthResponse response = authService.register(new RegisterRequest(
                "  Test Traders ", "INR", " INV ", " Owner@Example.COM ", "password123"));

        ArgumentCaptor<AppUser> savedUser = ArgumentCaptor.forClass(AppUser.class);
        verify(userRepository).save(savedUser.capture());
        AppUser owner = savedUser.getValue();
        assertThat(owner.getEmail()).isEqualTo("owner@example.com");
        assertThat(owner.getRole()).isEqualTo(Role.OWNER);
        assertThat(owner.getBusiness().getName()).isEqualTo("Test Traders");
        assertThat(owner.getBusiness().getInvoicePrefix()).isEqualTo("INV");
        assertThat(owner.getPasswordHash()).isNotEqualTo("password123");
        assertThat(passwordEncoder.matches("password123", owner.getPasswordHash())).isTrue();
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(jwtService.parseUserId(response.accessToken())).isEqualTo(Optional.of(20L));
    }

    @Test
    void registerRejectsAnEmailThatIsAlreadyTaken() {
        when(userRepository.existsByEmail("owner@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(new RegisterRequest(
                "Test Traders", "INR", "INV", "owner@example.com", "password123")))
                .isInstanceOf(EmailAlreadyRegisteredException.class);

        verifyNoInteractions(businessRepository);
        verify(userRepository, never()).save(any());
    }

    @Test
    void loginWithCorrectCredentialsReturnsAWorkingToken() {
        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(storedUser(true)));

        AuthResponse response = authService.login(new LoginRequest("Owner@Example.com", "password123"));

        assertThat(jwtService.parseUserId(response.accessToken())).isEqualTo(Optional.of(5L));
    }

    @Test
    void loginWithUnknownEmailIsRejected() {
        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("nobody@example.com", "password123")))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void loginWithWrongPasswordIsRejected() {
        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(storedUser(true)));

        failLogin();
    }

    @Test
    void loginForADisabledUserIsRejectedEvenWithTheRightPassword() {
        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(storedUser(false)));

        assertThatThrownBy(() -> authService.login(new LoginRequest("owner@example.com", "password123")))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void loginIsBlockedAfterFiveFailuresEvenWithTheCorrectPassword() {
        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(storedUser(true)));

        for (int i = 0; i < 5; i++) {
            failLogin();
        }

        assertThatThrownBy(() -> authService.login(new LoginRequest("owner@example.com", "password123")))
                .isInstanceOf(TooManyLoginAttemptsException.class);
    }

    @Test
    void aSuccessfulLoginResetsTheFailureCount() {
        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(storedUser(true)));

        for (int i = 0; i < 4; i++) {
            failLogin();
        }
        authService.login(new LoginRequest("owner@example.com", "password123"));

        for (int i = 0; i < 4; i++) {
            failLogin();
        }
    }
}
