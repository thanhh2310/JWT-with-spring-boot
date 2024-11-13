package com.example.demo_jwt.controller;

import com.example.demo_jwt.dto.AuthResponse;
import com.example.demo_jwt.dto.LoginRequest;
import com.example.demo_jwt.dto.RegisterRequest;
import com.example.demo_jwt.entity.User;
import com.example.demo_jwt.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.AuthenticationException;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://127.0.0.1:5500", "http://localhost:5500"}, allowCredentials = "true")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final EntityManager entityManager;

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            // Check if username already exists
            if (entityManager.createQuery("SELECT COUNT(u) FROM User u WHERE u.username = :username", Long.class)
                    .setParameter("username", request.getUsername())
                    .getSingleResult() > 0) {
                return ResponseEntity.badRequest()
                    .body(new AuthResponse(null, "Username already exists"));
            }

            // Create new user
            User user = User.builder()
                    .username(request.getUsername())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .email(request.getEmail())
                    .build();

            entityManager.persist(user);
            
            return ResponseEntity.ok(new AuthResponse(null, "User registered successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(new AuthResponse(null, "Registration failed: " + e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            String token = jwtUtil.generateToken(request.getUsername());
            return ResponseEntity.ok(new AuthResponse(token, "Login successful"));
            
        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest()
                .body(new AuthResponse(null, "Invalid username or password"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(new AuthResponse(null, "Login failed: " + e.getMessage()));
        }
    }
} 