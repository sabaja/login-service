package com.login.service;

import com.login.repository.UserRepository;
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
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthServiceImplTest {

    private AuthService authService;
    private UserDetails user;
    private Authentication authentication;


    @BeforeEach
    void setUp() {
        this.user = createUserDetails();
        this.authentication = createAuthentication(user);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        UserRepository userRepository = mock(UserRepository.class);
        this.authService = new AuthServiceImpl(passwordEncoder, userRepository);
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
    void loadUserByUsername() {
    }

    @Test
    void saveUser() {
    }

    private UserDetails createUserDetails() {
        return new User("USER", "password", List.of(new SimpleGrantedAuthority("USER_ROLE")));
    }

    private Authentication createAuthentication(UserDetails user) {
        return new TestingAuthenticationToken(user.getUsername(), user.getPassword(), new ArrayList<GrantedAuthority>(user.getAuthorities()));
    }
}