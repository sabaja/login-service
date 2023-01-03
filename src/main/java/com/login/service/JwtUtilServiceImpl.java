package com.login.service;

import com.login.exception.JwtTokenMalformedException;
import com.login.exception.JwtTokenMissingException;
import com.login.exception.UserException;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.function.Function;

@Service
@Slf4j
public class JwtUtilServiceImpl implements JwtUtilService {

    public static final String EXPIRED_JWT_TOKEN_ERROR_MESSAGE = "Expired JWT token";
    public static final String INVALID_JWT_TOKEN_ERROR_MESSAGE = "Invalid JWT token";
    public static final String JWT_CLAIMS_STRING_IS_EMPTY_ERROR_MESSAGE = "JWT claims string is empty.";
    public static final String UNSUPPORTED_JWT_TOKEN_ERROR_MESSAGE = "Unsupported JWT token";
    public static final String USER_IS_NULL_ERROR_MESSAGE = "User is null";
    private static final String JWT_SIGNING_KEY = "c2VjcmV0cGFzc3dvcmQ=";
    private static final long TOKEN_VALIDITY = 1000L * 60L * 60L * 10L;
    private final byte[] encodedJwtSigningKey;

    public JwtUtilServiceImpl() {
        this.encodedJwtSigningKey = Base64.getDecoder().decode(JWT_SIGNING_KEY);
    }

    /**
     * @deprecated Use {@link #getUsername(String)} method instead.
     */
    @Override
    @Deprecated(since = "Use getUsername", forRemoval = true)
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public String getUsername(final String token) {
        try {
            Claims body = Jwts.parser()
                    .setSigningKey(JWT_SIGNING_KEY)
                    .parseClaimsJws(token)
                    .getBody();
            return body.getSubject();
        } catch (Exception e) {
            log.error(e.getMessage() + " => " + e);
            throw new UserException(e.getMessage() + " => " + e);
        }
    }

    @Override
    public LocalDateTime extractExpirationDate(String token) {
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
    public String generateToken(Authentication authentication) {
        final String username = String.valueOf(authentication.getPrincipal());
        final Claims claims = Jwts.claims().setSubject(username);
        return createToken(claims, username);
    }

    @Override
    public Boolean validateToken(String token, UserDetails userDetails) {
        validateToken(token);
        validateUserDetails(userDetails);
        final String username = getUsername(token);
        return (username.equals(userDetails.getUsername()));
    }

    private void validateUserDetails(UserDetails userDetails) {
        if (Objects.isNull(userDetails)) {
            throw new UserException(USER_IS_NULL_ERROR_MESSAGE);
        }
    }

    private void validateToken(final String token) {
        try {
            Jwts.parser().setSigningKey(encodedJwtSigningKey).parseClaimsJws(token);
        } catch (SignatureException | MalformedJwtException ex) {
            throw new JwtTokenMalformedException(INVALID_JWT_TOKEN_ERROR_MESSAGE);
        } catch (ExpiredJwtException ex) {
            throw new JwtTokenMalformedException(EXPIRED_JWT_TOKEN_ERROR_MESSAGE);
        } catch (UnsupportedJwtException ex) {
            throw new JwtTokenMalformedException(UNSUPPORTED_JWT_TOKEN_ERROR_MESSAGE);
        } catch (IllegalArgumentException ex) {
            throw new JwtTokenMissingException(JWT_CLAIMS_STRING_IS_EMPTY_ERROR_MESSAGE);
        }
    }

    /*
        https://stackoverflow.com/questions/50691187/spring-security-sessions-without-cookies/50857373#50857373
    */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(encodedJwtSigningKey)
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final LocalDateTime localDateTime = extractExpirationDate(token);
        return Objects.isNull(localDateTime) ? Boolean.TRUE : localDateTime.isBefore(LocalDateTime.now());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY))
                .signWith(SignatureAlgorithm.HS512, encodedJwtSigningKey)
                .compact();
    }

    private LocalDateTime convertToLocalDateTime(Date extractClaim) {
        return extractClaim.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }


}
