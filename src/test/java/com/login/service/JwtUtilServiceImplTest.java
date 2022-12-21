package com.login.service;

import com.login.controller.model.CourseUser;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;


class JwtUtilServiceImplTest {

    @Mock
    private Jwts jwts;

    private JwtUtilServiceImpl jwtUtilService;

    @BeforeEach
    void setUp() {
        this.jwtUtilService = new JwtUtilServiceImpl();
    }

    @Test
    void shouldExtractClaim() {
    }

    @Test
    void shouldGenerateToken() {
        final String token = jwtUtilService.generateToken(createUserDetails());
        assertNotNull(token);

    }

    private UserDetails createUserDetails() {
        return new CourseUser("USER", "password", List.of(new SimpleGrantedAuthority("USER_ROLE")));
    }
}