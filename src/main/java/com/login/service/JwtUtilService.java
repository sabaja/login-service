package com.login.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.function.Function;

public interface JwtUtilService {

    String extractUsername(String token);

    LocalDateTime extractExpirationDate(String token);

    <T> T extractClaim(String token, Function<Claims, T> claimsResolver);

    String getUsername(String token);

    String generateToken(UserDetails userDetails);

    String generateToken(Authentication authentication);

    Boolean validateToken(String token, UserDetails userDetails);
}
