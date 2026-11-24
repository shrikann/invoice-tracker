package com.shri.invoicetracker.security;

import com.shri.invoicetracker.user.Role;

public record AuthenticatedUser(Long userId, Long businessId, String email, Role role) {
}
