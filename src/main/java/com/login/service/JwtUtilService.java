package com.login.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.function.Function;

public interface JwtUtilService {
    String extractUsername(String token);

    LocalDateTime extractExpiration(String token);

    <T> T extractClaim(String token, Function<Claims, T> claimsResolver);

    String generateToken(UserDetails userDetails);

    Boolean validateToken(String token, UserDetails userDetails);
}
