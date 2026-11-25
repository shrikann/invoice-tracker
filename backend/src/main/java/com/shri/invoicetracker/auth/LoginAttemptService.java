package com.shri.invoicetracker.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Basic in-memory brute-force protection: MAX_FAILED_ATTEMPTS failed logins for the
 * same email within WINDOW lock that email for WINDOW. State is lost on restart and
 * is not shared between application instances.
 */
@Service
public class LoginAttemptService {

    static final int MAX_FAILED_ATTEMPTS = 5;
    static final Duration WINDOW = Duration.ofMinutes(15);
    private static final int PURGE_THRESHOLD = 10_000;

    private record Attempts(int failures, Instant windowStart, Instant lockedUntil) {
    }

    private final Clock clock;
    private final ConcurrentHashMap<String, Attempts> attemptsByEmail = new ConcurrentHashMap<>();

    @Autowired
    public LoginAttemptService() {
        this(Clock.systemUTC());
    }

    LoginAttemptService(Clock clock) {
        this.clock = clock;
    }

    public boolean isBlocked(String email) {
        Attempts attempts = attemptsByEmail.get(email);
        return attempts != null
                && attempts.lockedUntil() != null
                && clock.instant().isBefore(attempts.lockedUntil());
    }

    public void recordFailure(String email) {
        Instant now = clock.instant();
        if (attemptsByEmail.size() >= PURGE_THRESHOLD) {
            attemptsByEmail.values().removeIf(attempts -> isStale(attempts, now));
        }
        attemptsByEmail.compute(email, (key, current) -> {
            if (current == null || isStale(current, now)) {
                return new Attempts(1, now, null);
            }
            if (current.lockedUntil() != null) {
                return current;
            }
            int failures = current.failures() + 1;
            Instant lockedUntil = failures >= MAX_FAILED_ATTEMPTS ? now.plus(WINDOW) : null;
            return new Attempts(failures, current.windowStart(), lockedUntil);
        });
    }

    public void reset(String email) {
        attemptsByEmail.remove(email);
    }

    private boolean isStale(Attempts attempts, Instant now) {
        if (attempts.lockedUntil() != null) {
            return !now.isBefore(attempts.lockedUntil());
        }
        return now.isAfter(attempts.windowStart().plus(WINDOW));
    }
}
