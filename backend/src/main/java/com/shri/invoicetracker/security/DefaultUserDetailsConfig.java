package com.shri.invoicetracker.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Spring Boot creates a default in-memory user with a generated password unless a
 * UserDetailsService bean exists. Authentication here is handled by AuthService and
 * JWTs, so this bean rejects every lookup and stops that default user from being created.
 */
@Configuration
public class DefaultUserDetailsConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            throw new UsernameNotFoundException("Password authentication is handled by AuthService");
        };
    }
}
