package com.login.service;

import com.login.model.AuthenticationRequest;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.function.Function;

public interface JwtUtilService extends UserDetailsService {

    LocalDateTime extractExpirationDate(String token);

    <T> T extractClaim(String token, Function<Claims, T> claimsResolver);

    String getUsername(String token);

    String generateToken(final UserDetails userDetails);

    String generateToken(final Authentication authentication, final UserDetails userDetails);

    String generateToken(final Authentication authentication, final UserDetails userDetails, final Date expiredDate);

    Boolean isTokenValid(String token, UserDetails userDetails);

    void isTokenValid(String token);

    boolean isAuthenticated();

    void saveUser(AuthenticationRequest request);

}
