package com.login.service;

import com.login.controller.model.Request;
import com.login.entity.Role;
import com.login.entity.User;
import com.login.exception.JwtTokenMalformedException;
import com.login.exception.JwtTokenMissingException;
import com.login.exception.UserException;
import com.login.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class JwtUtilServiceImpl implements JwtUtilService {

    public static final String EXPIRED_JWT_TOKEN_ERROR_MESSAGE = "Expired JWT token";
    public static final String INVALID_JWT_TOKEN_ERROR_MESSAGE = "Invalid JWT token";
    public static final String JWT_CLAIMS_STRING_IS_EMPTY_ERROR_MESSAGE = "JWT claims string is empty.";
    public static final String UNSUPPORTED_JWT_TOKEN_ERROR_MESSAGE = "Unsupported JWT token";
    public static final String USER_IS_NULL_ERROR_MESSAGE = "User is null";
    public static final String USERNAME_CANNOT_BE_NULL_ERROR_MESSAGE = "Username cannot be null";
    public static final String USER_MUST_BE_NOT_EMPTY_ERROR_MESSAGE = "User must be not empty";
    public static final String USER_ALREADY_EXISTS_ERROR_MESSAGE = "User already exists";
    public static final String PASSWORD_CANNOT_BE_EMPTY_ERROR_MESSAGE = "Password cannot be empty";
    public static final String REQUEST_IS_NULL_ERROR_MESSAGE = "Request is null";
    public static final String ROLES_NOT_FOUND_ERROR_MESSAGE = "Roles not found";

    // https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx 512-bit + hex
    private static final String JWT_SIGNING_KEY = "5A7134743777217A25432A462D4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970337336763979244226452948404D63516654";
    private static final long TOKEN_VALIDITY = 1000L * 60L * 60L * 10L;
    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    @Override
    public String getUsername(final String token) {
        try {
            Claims body = Jwts.
                    parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return Optional.ofNullable(body.getSubject())
                    .filter(StringUtils::isNotBlank)
                    .orElseThrow(() -> new JwtTokenMissingException("Missing Subject"));
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
    public String generateToken(final Authentication authentication, UserDetails userDetails) {
        final String principal = String.valueOf(authentication.getPrincipal());
        final Claims claims = Jwts.claims().setSubject(principal);
        return createToken(claims, userDetails.getUsername());
    }

    @Override
    public Boolean isTokenValid(String token, UserDetails userDetails) {
        isTokenValid(token);
        validateUserDetails(userDetails);
        final String username = getUsername(token);
        return (username.equals(userDetails.getUsername()));
    }

    @Override
    public void isTokenValid(final String token) {
        try {
            Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token);
        } catch (MalformedJwtException ex) {
            throw new JwtTokenMalformedException(INVALID_JWT_TOKEN_ERROR_MESSAGE);
        } catch (ExpiredJwtException ex) {
            throw new JwtTokenMalformedException(EXPIRED_JWT_TOKEN_ERROR_MESSAGE);
        } catch (UnsupportedJwtException ex) {
            throw new JwtTokenMalformedException(UNSUPPORTED_JWT_TOKEN_ERROR_MESSAGE);
        } catch (IllegalArgumentException ex) {
            throw new JwtTokenMissingException(JWT_CLAIMS_STRING_IS_EMPTY_ERROR_MESSAGE);
        }
    }

    @Override
    public boolean isAuthenticated() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return null != authentication && !("anonymousUser").equals(authentication.getName());
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (StringUtils.isEmpty(username)) {
            throw new UserException(USERNAME_CANNOT_BE_NULL_ERROR_MESSAGE);
        }

        final User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found"));
        List<Role> roles = user.getRoles()
                .stream()
                .toList();
        final List<SimpleGrantedAuthority> grantedAuthorities = roles.stream()
                .map(r -> new SimpleGrantedAuthority(r.getType())
                ).toList();

        return new org.springframework.security.core.userdetails.User(username, user.getUserPass(), grantedAuthorities);
    }

    @Override
    @Transactional
    public void saveUser(Request request) {

        if (request == null) {
            throw new UserException(REQUEST_IS_NULL_ERROR_MESSAGE);
        }

        final String userName = Optional.of(request)
                .map(Request::getUserName)
                .filter(StringUtils::isNotBlank)
                .orElseThrow(() -> new UserException(USER_MUST_BE_NOT_EMPTY_ERROR_MESSAGE));

        if (userRepository.findByUserName(userName).isPresent()) {
            throw new UserException(USER_ALREADY_EXISTS_ERROR_MESSAGE);
        }

        final LocalDateTime now = LocalDateTime.now();
        User user = new User();
        user.setUserName(userName);
        user.setUserPass(passwordEncoder.encode(getPassword(request)));
        user.setCreateTime(now);

        user.setRoles(getRoles(request).stream().map(r -> {
            Role role = new Role();
            role.setType(r);
            role.setUser(user);
            role.setCreateTime(now);
            return role;
        }).collect(Collectors.toSet()));

        userRepository.save(user);
    }

    private void validateUserDetails(UserDetails userDetails) {
        if (Objects.isNull(userDetails)) {
            throw new UserException(USER_IS_NULL_ERROR_MESSAGE);
        }
    }

    /*
        https://stackoverflow.com/questions/50691187/spring-security-sessions-without-cookies/50857373#50857373
    */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY))
                .signWith(getSignInKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    private LocalDateTime convertToLocalDateTime(Date extractClaim) {
        return extractClaim.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }

    private List<String> getRoles(Request request) {
        return Optional.ofNullable(request.getRoles())
                .orElseThrow(() -> new UserException(ROLES_NOT_FOUND_ERROR_MESSAGE));
    }

    private String getPassword(Request request) {
        return Optional.ofNullable(request.getUserPwd())
                .filter(StringUtils::isNotBlank)
                .orElseThrow(() -> new UserException(PASSWORD_CANNOT_BE_EMPTY_ERROR_MESSAGE));
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SIGNING_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
