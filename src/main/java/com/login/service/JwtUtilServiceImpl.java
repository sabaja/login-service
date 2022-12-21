package com.login.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtUtilServiceImpl implements JwtUtilService {

    private static final String jwtSigningKey = "c2VjcmV0cGFzc3dvcmQ=";

    final byte[] encodedJwtSigningKey;

    public JwtUtilServiceImpl() {
        this.encodedJwtSigningKey = Base64.getDecoder().decode(jwtSigningKey);
    }

    @Override
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public LocalDateTime extractExpiration(String token) {
        final Date extractClaim = extractClaim(token, Claims::getExpiration);
        return extractClaim != null ? convertToLocalDateTime(extractClaim) : null;
    }

    @Override
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    @Override
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(encodedJwtSigningKey)
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final LocalDateTime localDateTime = extractExpiration(token);
        return Objects.isNull(localDateTime) ? Boolean.TRUE : localDateTime.isBefore(LocalDateTime.now());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, encodedJwtSigningKey)
                .compact();
    }

    private LocalDateTime convertToLocalDateTime(Date extractClaim) {
        return extractClaim.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }
}
