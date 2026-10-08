package com.example.demo.security;


import java.io.IOException;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    public OAuth2AuthenticationSuccessHandler(UserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();

        String registrationId = oauthToken.getAuthorizedClientRegistrationId(); // "google" or "github"
        String email = oAuth2User.getAttribute("email");
        
        // Handle GitHub edge case where primary email might require fallback
        if (email == null && "github".equalsIgnoreCase(registrationId)) {
            email = oAuth2User.getAttribute("login") + "@github.com";
        }

        final String finalEmail = email;
        User user = userRepository.findByEmail(finalEmail).orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(finalEmail);
            newUser.setProvider(User.AuthProvider.valueOf(registrationId.toUpperCase()));
            newUser.setProviderId(oAuth2User.getName());
            newUser.setRoles(Set.of(User.Role.ROLE_USER));
            return userRepository.save(newUser);
        });

        // Convert User entity to CustomUserDetails
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String accessToken = jwtService.generateAccessToken(userDetails);

        // Redirect user to front-end app with token (or set as HttpOnly cookie)
        String redirectUrl = "/api/v1/user/profile?token=" + accessToken;
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}
