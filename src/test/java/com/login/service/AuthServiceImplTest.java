package com.login.service;

import com.login.controller.model.Request;
import com.login.entity.UserRole;
import com.login.exception.UserException;
import com.login.repository.UserRepository;
import com.sun.istack.NotNull;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
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

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class AuthServiceImplTest {

    private static final String USER = "USER";
    private static final String PASS = "PASS";
    private static final String USER_ROLE = "USER_ROLE";
    private AuthServiceImpl authService;
    private UserDetails user;
    private Authentication authentication;

    private PasswordEncoder passwordEncoder;

    @Mock
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        this.user = createUserDetails();
        this.authentication = createAuthentication(user);
        this.passwordEncoder = mock(PasswordEncoder.class);
        userRepository = mock(UserRepository.class);
        this.authService = new AuthServiceImpl(passwordEncoder, userRepository);
        SecurityContextHolder.clearContext();

    }

    //https://stackoverflow.com/questions/360520/unit-testing-with-spring-security
    @Test
    void shouldVerifyIsAuthenticated() {
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        final boolean authenticated = authService.isAuthenticated();
        assertTrue(authenticated);
    }

    @Test
    void shouldVerifyIsAnonymousUser() {
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(createAnonymousUser());
        final boolean authenticated = authService.isAuthenticated();
        assertFalse(authenticated);
    }

    @Test
    void shouldVerifyIsNotAuthenticated() {
        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
        final boolean authenticated = authService.isAuthenticated();
        assertFalse(authenticated);
    }

    @Test
    void throwUserNullOrEmptyException_whenLoadUserByUsername() {
        Exception exception = assertThrows(UserException.class, () -> authService.loadUserByUsername(Strings.EMPTY));
        final String actualMessage = exception.getMessage();
        assertEquals(AuthServiceImpl.USERNAME_CANNOT_BE_NULL_ERROR_MESSAGE, actualMessage);
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

        final UserDetails userDetails = authService.loadUserByUsername(USER);

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

        authService.saveUser(createRequest());

        verify(userRepository, times(1)).findByUserName(anyString());
        verify(userRepository, times(1)).save(any(com.login.entity.User.class));
        verify(passwordEncoder, times(1)).encode(anyString());
    }

    @NotNull
    private Request createRequest() {
        Request request = new Request();
        request.setUserName(USER);
        request.setUserPwd(PASS);
        request.setRoles(List.of("USER_ROLE"));
        return request;
    }

    @NotNull
    private Optional<com.login.entity.User> createUser() {
        com.login.entity.User user = new com.login.entity.User();
        user.setId(1);
        user.setUserName(USER);
        user.setUserPass(PASS);
        com.login.entity.UserRole userRole = new UserRole();
        userRole.setId(1);
        userRole.setRole(USER_ROLE);
        userRole.setUser(user);
        final Set<UserRole> userRoles = new HashSet<>();
        userRoles.add(userRole);
        user.setUserRoles(userRoles);
        return Optional.of(user);
    }

    @NotNull
    private UserDetails createUserDetails() {
        return new User(USER, "password", List.of(new SimpleGrantedAuthority(USER_ROLE)));
    }

    @NotNull
    private Authentication createAuthentication(UserDetails user) {
        return new TestingAuthenticationToken(user.getUsername(), user.getPassword(), new ArrayList<GrantedAuthority>(user.getAuthorities()));
    }

    @NotNull
    private Authentication createAnonymousUser() {
        final User user = new User("anonymousUser", "password", List.of(new SimpleGrantedAuthority(USER_ROLE)));
        return new TestingAuthenticationToken(user.getUsername(), user.getPassword(), new ArrayList<GrantedAuthority>(user.getAuthorities()));
    }
}