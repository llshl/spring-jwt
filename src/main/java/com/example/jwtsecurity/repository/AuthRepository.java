package com.example.jwtsecurity.repository;

import com.example.jwtsecurity.entity.Auth;
import com.example.jwtsecurity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthRepository extends JpaRepository<Auth, Long> {
    Optional<Auth> findByUserId(Long userId);
}
