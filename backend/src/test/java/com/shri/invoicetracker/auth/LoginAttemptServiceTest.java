package com.shri.invoicetracker.auth;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class LoginAttemptServiceTest {

    private static class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private final MutableClock clock = new MutableClock();
    private final LoginAttemptService service = new LoginAttemptService(clock);

    private void fail(String email, int times) {
        for (int i = 0; i < times; i++) {
            service.recordFailure(email);
        }
    }

    @Test
    void freshEmailIsNotBlocked() {
        assertThat(service.isBlocked("a@example.com")).isFalse();
    }

    @Test
    void fourFailuresDoNotBlock() {
        fail("a@example.com", 4);

        assertThat(service.isBlocked("a@example.com")).isFalse();
    }

    @Test
    void fiveFailuresBlock() {
        fail("a@example.com", 5);

        assertThat(service.isBlocked("a@example.com")).isTrue();
    }

    @Test
    void lockExpiresAfterFifteenMinutes() {
        fail("a@example.com", 5);

        clock.advance(Duration.ofMinutes(14));
        assertThat(service.isBlocked("a@example.com")).isTrue();

        clock.advance(Duration.ofMinutes(1));
        assertThat(service.isBlocked("a@example.com")).isFalse();
    }

    @Test
    void failuresOutsideTheWindowDoNotAccumulate() {
        fail("a@example.com", 4);
        clock.advance(Duration.ofMinutes(16));
        fail("a@example.com", 1);

        assertThat(service.isBlocked("a@example.com")).isFalse();
    }

    @Test
    void resetClearsTheFailureCount() {
        fail("a@example.com", 4);
        service.reset("a@example.com");
        fail("a@example.com", 4);

        assertThat(service.isBlocked("a@example.com")).isFalse();
    }

    @Test
    void emailsAreTrackedIndependently() {
        fail("a@example.com", 5);

        assertThat(service.isBlocked("a@example.com")).isTrue();
        assertThat(service.isBlocked("b@example.com")).isFalse();
    }
}
