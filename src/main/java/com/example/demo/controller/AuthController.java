package com.example.demo.controller;

import java.util.Optional;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dto.AuthDTOs.AuthResponse;
import com.example.demo.dto.AuthDTOs.LoginRequest;
import com.example.demo.dto.AuthDTOs.RefreshTokenRequest;
import com.example.demo.dto.AuthDTOs.RegisterRequest;
import com.example.demo.model.User;
import com.example.demo.model.User.AuthProvider;
import com.example.demo.model.User.Role;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.CustomUserDetails;
import com.example.demo.security.JwtService;
import com.example.demo.security.RefreshToken;
import com.example.demo.service.RefreshTokenService;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            RefreshTokenService refreshTokenService
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        Role assignedRole = "ROLE_ADMIN".equalsIgnoreCase(request.role()) ? Role.ROLE_ADMIN : Role.ROLE_USER;

        User user = new User();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRoles(Set.of(assignedRole));
        user.setProvider(AuthProvider.LOCAL);

        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        User user = userDetails.getUser();

        String accessToken = jwtService.generateAccessToken(userDetails);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken.getToken())
                .httpOnly(true)
                .secure(false)
                .path("/api/v1/auth")
                .maxAge(7 * 24 * 60 * 60)
                .sameSite("Strict")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        String userRole = user.getRoles().stream().findFirst().map(Enum::name).orElse("ROLE_USER");
        return ResponseEntity.ok(new AuthResponse(accessToken, user.getEmail(), userRole));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            @CookieValue(name = "refreshToken", required = false) String cookieToken,
            @RequestBody(required = false) RefreshTokenRequest request
    ) {
        String token = (cookieToken != null) ? cookieToken : (request != null ? request.refreshToken() : null);

        if (token == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Refresh token missing");
        }

        Optional<RefreshToken> optionalToken = refreshTokenService.findByToken(token);
        if (optionalToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid refresh token");
        }

        RefreshToken refreshToken = refreshTokenService.verifyExpiration(optionalToken.get());
        User user = refreshToken.getUser();

        CustomUserDetails userDetails = new CustomUserDetails(user);
        String newAccessToken = jwtService.generateAccessToken(userDetails);
        String userRole = user.getRoles().stream().findFirst().map(Enum::name).orElse("ROLE_USER");

        return ResponseEntity.ok(new AuthResponse(newAccessToken, user.getEmail(), userRole));
    }
}