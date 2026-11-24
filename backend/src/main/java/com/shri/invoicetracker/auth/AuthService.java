package com.shri.invoicetracker.auth;

import com.shri.invoicetracker.business.Business;
import com.shri.invoicetracker.business.BusinessRepository;
import com.shri.invoicetracker.security.JwtService;
import com.shri.invoicetracker.user.AppUser;
import com.shri.invoicetracker.user.Role;
import com.shri.invoicetracker.user.UserRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Optional;

@Service
public class AuthService {

    private static final String TOKEN_TYPE = "Bearer";

    private final UserRepository userRepository;
    private final BusinessRepository businessRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    // Checked against when the email is unknown, so unknown and known emails take similar time.
    private final String dummyHash;

    public AuthService(UserRepository userRepository,
                       BusinessRepository businessRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.businessRepository = businessRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.dummyHash = passwordEncoder.encode("not-a-real-password");
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyRegisteredException();
        }

        Business business = new Business();
        business.setName(request.businessName().trim());
        business.setCurrency(request.currency());
        business.setInvoicePrefix(request.invoicePrefix().trim());
        business = businessRepository.save(business);

        AppUser owner = new AppUser();
        owner.setBusiness(business);
        owner.setEmail(email);
        owner.setPasswordHash(passwordEncoder.encode(request.password()));
        owner.setRole(Role.OWNER);
        owner = userRepository.save(owner);

        return new AuthResponse(jwtService.generateToken(owner.getId()), TOKEN_TYPE);
    }

    public AuthResponse login(LoginRequest request) {
        Optional<AppUser> user = userRepository.findByEmail(normalizeEmail(request.email()));

        String hashToCheck = user.map(AppUser::getPasswordHash).orElse(dummyHash);
        boolean passwordMatches = passwordEncoder.matches(request.password(), hashToCheck);

        if (user.isEmpty() || !passwordMatches || !user.get().isEnabled()) {
            throw new BadCredentialsException("Invalid email or password");
        }

        return new AuthResponse(jwtService.generateToken(user.get().getId()), TOKEN_TYPE);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
