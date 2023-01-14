package com.login.service;

import com.login.controller.model.Request;
import com.login.entity.Role;
import com.login.exception.JwtTokenMalformedException;
import com.login.exception.JwtTokenMissingException;
import com.login.exception.UserException;
import com.login.repository.UserRepository;
import com.sun.istack.NotNull;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.*;

import static com.login.service.JwtUtilServiceImpl.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;


class JwtUtilServiceImplTest {

    private static final String USER = "USER";
    private static final String PASS = "PASS";
    private static final String USER_ROLE = "USER_ROLE";
    private final String TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NzIzNDU0ODcsImlhdCI6MTY3MjMwOTQ4N30.M9YX0U4AEM2ZmiDnJ3jTUJYfRtNzXdi8KFM9qpw0k10";
    private final String UNSUPPORTED_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6ImludmFsaWRUeXBlIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.xJYP_PkUlAOXY6uNZNA8Q9uMMej8yxehRkEcZVfDUDE";
    private String invalidToken;
    private JwtUtilService jwtUtilService;
    private UserDetails user;
    private String jwtToken;
    private Authentication authentication;

    private PasswordEncoder passwordEncoder;

    private UserRepository userRepository;

    @BeforeEach
    public void setUp() {
        this.user = createUserDetails();
        this.authentication = createAuthentication(user);
        this.invalidToken = createInvalidToken();
        this.passwordEncoder = mock(PasswordEncoder.class);
        this.userRepository = mock(UserRepository.class);
        this.jwtUtilService = new JwtUtilServiceImpl(this.passwordEncoder, this.userRepository);
        this.jwtToken = jwtUtilService.generateToken(authentication, user);
        SecurityContextHolder.clearContext();
    }

    @Test
    void throwException_whenGetUsernameWithExpiredToken() {
        Exception exception = assertThrows(UserException.class, () -> jwtUtilService.getUsername(TOKEN));
        final String exceptionMessage = "JWT expired";
        final String actualMessage = exception.getMessage();
        assertTrue(actualMessage.contains(exceptionMessage));
    }

    @Test
    void shouldGetUsername() {
        //given
        //when
        final String userName = jwtUtilService.getUsername(jwtToken);

        //then
        assertNotNull(userName);
        assertEquals(user.getUsername(), userName);
    }

    @Test
    void shouldGenerateToken() {
        //given
        //when
        final String jwtToken = jwtUtilService.generateToken(user);

        //then
        assertNotNull(jwtToken);
    }

    @Test
    void shouldExtractExpirationDate() {
        //given
        //when
        final LocalDateTime expirationDate = jwtUtilService.extractExpirationDate(jwtToken);
        assertNotNull(expirationDate);
        assertTrue(LocalDateTime.now().isBefore(expirationDate));
    }

    @Test
    void shouldValidateToken() {
        Exception exception1 = assertThrows(JwtTokenMalformedException.class, () -> jwtUtilService.validateToken(TOKEN, user));
        assertTrue(exception1.getMessage().contains(EXPIRED_JWT_TOKEN_ERROR_MESSAGE));

        Exception exception2 = assertThrows(JwtTokenMalformedException.class, () -> jwtUtilService.validateToken("WrongToken", user));
        assertTrue(exception2.getMessage().contains(INVALID_JWT_TOKEN_ERROR_MESSAGE));

        Exception exception3 = assertThrows(JwtTokenMalformedException.class, () -> jwtUtilService.validateToken(invalidToken, user));
        assertTrue(exception3.getMessage().contains(INVALID_JWT_TOKEN_ERROR_MESSAGE));

        Exception exception4 = assertThrows(JwtTokenMissingException.class, () -> jwtUtilService.validateToken(Strings.EMPTY, user));
        assertTrue(exception4.getMessage().contains(JWT_CLAIMS_STRING_IS_EMPTY_ERROR_MESSAGE));

        Exception exception5 = assertThrows(UserException.class, () -> jwtUtilService.validateToken(jwtToken, null));
        assertTrue(exception5.getMessage().contains(USER_IS_NULL_ERROR_MESSAGE));

//        Exception exception6 = assertThrows(JwtTokenMalformedException.class, () -> jwtUtilService.validateToken(UNSUPPORTED_TOKEN, user));
//        assertTrue(exception6.getMessage().contains(UNSUPPORTED_JWT_TOKEN_ERROR_MESSAGE));


        final Boolean isValidate1 = jwtUtilService.validateToken(jwtToken, user);
        assertTrue(isValidate1);

        final Boolean isValidate2 = jwtUtilService.validateToken(jwtToken, new User("TOM", "NoPassword", List.of(new SimpleGrantedAuthority("USER_ROLE"))));
        assertFalse(isValidate2);


    }

    //https://stackoverflow.com/questions/360520/unit-testing-with-spring-security
    @Test
    void shouldVerifyIsAuthenticated() {
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        final boolean authenticated = jwtUtilService.isAuthenticated();
        assertTrue(authenticated);
    }

    @Test
    void shouldVerifyIsAnonymousUser() {
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(createAnonymousUser());
        final boolean authenticated = jwtUtilService.isAuthenticated();
        assertFalse(authenticated);
    }

    @Test
    void shouldVerifyIsNotAuthenticated() {
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
        final boolean authenticated = jwtUtilService.isAuthenticated();
        assertFalse(authenticated);
    }


    @Test
    void throwUserNullOrEmptyException_whenLoadUserByUsername() {
        Exception exception = assertThrows(UserException.class, () -> jwtUtilService.loadUserByUsername(Strings.EMPTY));
        final String actualMessage = exception.getMessage();
        assertEquals(USERNAME_CANNOT_BE_NULL_ERROR_MESSAGE, actualMessage);
    }

    @Test
    void throwUsernameNotFoundExceptionException_whenLoadUserByUsername() {
        // Arrange
        String username = "invalid_username";

        // Act and assert
        final UsernameNotFoundException usernameNotFoundException = assertThrows(UsernameNotFoundException.class, () -> {
            userRepository.findByUserName(username).orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found"));
        });

        assertEquals(usernameNotFoundException.getMessage(), "User " + username + " not found");
    }

    @Test
    void loadUserByUsername() {
        when(userRepository.findByUserName(anyString())).thenReturn(createUser());

        final UserDetails userDetails = jwtUtilService.loadUserByUsername(USER);

        assertEquals(USER, userDetails.getUsername());
        assertEquals(PASS, userDetails.getPassword());
        final Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        assertEquals(1, authorities.size());
        assertTrue(authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(auth -> StringUtils.equals(USER_ROLE, auth)));
    }

    @Test
    void saveUser() {
//        final Optional<com.login.entity.User> user = createUser();

//        when(userRepository.save(any())).thenReturn(user);

        jwtUtilService.saveUser(createRequest());

        verify(userRepository, times(1)).findByUserName(anyString());
        verify(userRepository, times(1)).save(any(com.login.entity.User.class));
        verify(passwordEncoder, times(1)).encode(anyString());
    }

    private UserDetails createUserDetails() {
        return new User("USER", "password", List.of(new SimpleGrantedAuthority("USER_ROLE")));
    }

    private Authentication createAuthentication(UserDetails user) {
        return new TestingAuthenticationToken(user.getUsername(), user.getPassword(), new ArrayList<GrantedAuthority>(user.getAuthorities()));
    }

    private String createInvalidToken() {
        String hmacSHA256Algorithm = "HmacSHA256";
        String data = "baeldung";
        String key = "123456";
        return new HmacUtils(hmacSHA256Algorithm, key).hmacHex(data);
    }

    @NotNull
    private Authentication createAnonymousUser() {
        final User user = new User("anonymousUser", "password", List.of(new SimpleGrantedAuthority(USER_ROLE)));
        return new TestingAuthenticationToken(user.getUsername(), user.getPassword(), new ArrayList<GrantedAuthority>(user.getAuthorities()));
    }

    @NotNull
    private Optional<com.login.entity.User> createUser() {
        com.login.entity.User user = new com.login.entity.User();
        user.setId(1L);
        user.setUserName(USER);
        user.setUserPass(PASS);
        Role role = new Role();
        role.setId(1L);
        role.setType(USER_ROLE);
        role.setUser(user);
        final Set<Role> roles = new HashSet<>();
        roles.add(role);
        user.setRoles(roles);
        return Optional.of(user);
    }

    @NotNull
    private Request createRequest() {
        Request request = new Request();
        request.setUserName(USER);
        request.setUserPwd(PASS);
        request.setRoles(List.of("USER_ROLE"));
        return request;
    }
}