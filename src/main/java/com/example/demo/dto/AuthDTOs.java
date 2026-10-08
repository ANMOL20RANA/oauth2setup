package com.example.demo.dto;

public class AuthDTOs {

    public record RegisterRequest(
        String email,
        String password,
        String role
    ) {}

    public record LoginRequest(
        String email,
        String password
    ) {}

    public record AuthResponse(
        String accessToken,
        String tokenType,
        String email,
        String role
    ) {
        public AuthResponse(String accessToken, String email, String role) {
            this(accessToken, "Bearer", email, role);
        }
    }

    public record RefreshTokenRequest(
        String refreshToken
    ) {}
}
