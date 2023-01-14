package com.login.service;

import com.login.controller.model.Request;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.time.LocalDateTime;
import java.util.function.Function;

public interface JwtUtilService extends UserDetailsService {

    LocalDateTime extractExpirationDate(String token);

    <T> T extractClaim(String token, Function<Claims, T> claimsResolver);

    String getUsername(String token);

    String generateToken(UserDetails userDetails);

    String generateToken(final Authentication authentication, UserDetails userDetails);

    Boolean validateToken(String token, UserDetails userDetails);

    void validateToken(String token);

    boolean isAuthenticated();

    void saveUser(Request request);
}
