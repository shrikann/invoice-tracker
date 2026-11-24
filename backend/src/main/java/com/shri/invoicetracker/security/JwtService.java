package com.shri.invoicetracker.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final Duration accessTokenLifetime;

    public JwtService(@Value("${app.jwt.secret}") String base64Secret,
                      @Value("${app.jwt.access-token-minutes}") long accessTokenMinutes) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        this.accessTokenLifetime = Duration.ofMinutes(accessTokenMinutes);
    }

    public String generateToken(Long userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTokenLifetime)))
                .signWith(signingKey)
                .compact();
    }

    /**
     * Returns the user id if the token is correctly signed and not expired,
     * otherwise an empty Optional.
     */
    public Optional<Long> parseUserId(String token) {
        try {
            String subject = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
            return Optional.of(Long.valueOf(subject));
        } catch (JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
