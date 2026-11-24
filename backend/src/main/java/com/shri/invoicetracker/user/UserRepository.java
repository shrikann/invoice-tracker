package com.shri.invoicetracker.user;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByEmail(String email);

    boolean existsByEmail(String email);

    @EntityGraph(attributePaths = "business")
    Optional<AppUser> findWithBusinessById(Long id);
}
