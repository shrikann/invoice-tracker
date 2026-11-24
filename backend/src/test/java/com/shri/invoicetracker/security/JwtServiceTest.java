package com.shri.invoicetracker.security;

import io.jsonwebtoken.io.Encoders;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private static final String SECRET = Encoders.BASE64.encode(
            "unit-test-secret-that-is-at-least-32-bytes-long".getBytes(StandardCharsets.UTF_8));
    private static final String OTHER_SECRET = Encoders.BASE64.encode(
            "another-unit-test-secret-also-over-32-bytes!!".getBytes(StandardCharsets.UTF_8));

    private final JwtService jwtService = new JwtService(SECRET, 30);

    @Test
    void validTokenReturnsTheUserId() {
        String token = jwtService.generateToken(42L);

        assertThat(jwtService.parseUserId(token)).isEqualTo(Optional.of(42L));
    }

    @Test
    void tokenSignedWithADifferentSecretIsRejected() {
        String token = new JwtService(OTHER_SECRET, 30).generateToken(42L);

        assertThat(jwtService.parseUserId(token)).isEmpty();
    }

    @Test
    void tokenWithSwappedPayloadIsRejected() {
        String[] genuine = jwtService.generateToken(1L).split("\\.");
        String[] other = jwtService.generateToken(2L).split("\\.");
        String forged = genuine[0] + "." + other[1] + "." + genuine[2];

        assertThat(jwtService.parseUserId(forged)).isEmpty();
    }

    @Test
    void expiredTokenIsRejected() {
        String token = new JwtService(SECRET, -1).generateToken(42L);

        assertThat(jwtService.parseUserId(token)).isEmpty();
    }

    @Test
    void garbageIsRejected() {
        assertThat(jwtService.parseUserId("not-a-jwt")).isEmpty();
    }
}
