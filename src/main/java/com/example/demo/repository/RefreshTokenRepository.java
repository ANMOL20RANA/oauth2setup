package com.example.demo.repository;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.model.User;
import com.example.demo.security.RefreshToken;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUser(User user); // Added for Upsert pattern

    Optional<RefreshToken> findByUserAndRevokedFalse(User user);

    @Modifying
    @Transactional
    int deleteByUser(User user);

    @Modifying
    @Transactional
    int deleteByExpiryDateBefore(Instant now);
}