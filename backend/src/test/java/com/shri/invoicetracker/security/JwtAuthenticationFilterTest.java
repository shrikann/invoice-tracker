package com.shri.invoicetracker.security;

import com.shri.invoicetracker.business.Business;
import com.shri.invoicetracker.user.AppUser;
import com.shri.invoicetracker.user.Role;
import com.shri.invoicetracker.user.UserRepository;
import io.jsonwebtoken.io.Encoders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private static final String SECRET = Encoders.BASE64.encode(
            "unit-test-secret-that-is-at-least-32-bytes-long".getBytes(StandardCharsets.UTF_8));

    private final JwtService jwtService = new JwtService(SECRET, 30);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtService, userRepository);

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private AppUser user(long id, long businessId, Role role, boolean enabled) {
        Business business = new Business();
        ReflectionTestUtils.setField(business, "id", businessId);

        AppUser user = new AppUser();
        ReflectionTestUtils.setField(user, "id", id);
        user.setBusiness(business);
        user.setEmail("user@example.com");
        user.setRole(role);
        user.setEnabled(enabled);
        return user;
    }

    private void run(String authorizationHeader) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (authorizationHeader != null) {
            request.addHeader("Authorization", authorizationHeader);
        }
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
    }

    @Test
    void validTokenAuthenticatesTheUserWithBusinessAndRole() throws Exception {
        when(userRepository.findWithBusinessById(7L))
                .thenReturn(Optional.of(user(7L, 3L, Role.ACCOUNTANT, true)));

        run("Bearer " + jwtService.generateToken(7L));

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        AuthenticatedUser principal = (AuthenticatedUser) authentication.getPrincipal();
        assertThat(principal.userId()).isEqualTo(7L);
        assertThat(principal.businessId()).isEqualTo(3L);
        assertThat(principal.role()).isEqualTo(Role.ACCOUNTANT);
        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ACCOUNTANT");
    }

    @Test
    void missingHeaderLeavesRequestUnauthenticated() throws Exception {
        run(null);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(userRepository);
    }

    @Test
    void nonBearerHeaderIsIgnored() throws Exception {
        run("Basic dXNlcjpwYXNz");

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(userRepository);
    }

    @Test
    void invalidTokenLeavesRequestUnauthenticated() throws Exception {
        run("Bearer garbage");

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(userRepository);
    }

    @Test
    void disabledUserIsNotAuthenticated() throws Exception {
        when(userRepository.findWithBusinessById(7L))
                .thenReturn(Optional.of(user(7L, 3L, Role.OWNER, false)));

        run("Bearer " + jwtService.generateToken(7L));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void tokenForUnknownUserIsNotAuthenticated() throws Exception {
        when(userRepository.findWithBusinessById(99L)).thenReturn(Optional.empty());

        run("Bearer " + jwtService.generateToken(99L));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
