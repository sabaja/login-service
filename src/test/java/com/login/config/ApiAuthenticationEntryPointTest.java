package com.login.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import static com.login.config.ApiAuthenticationEntryPoint.UNAUTHORIZED_MESSAGE_ERROR;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ApiAuthenticationEntryPointTest {


    private AuthenticationEntryPoint authenticationEntryPoint;

    @BeforeEach
    void setUp() {
        this.authenticationEntryPoint = new ApiAuthenticationEntryPoint();
    }

    @SneakyThrows
    @Test
    void shouldCommence() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticationException authException = mock(AuthenticationException.class);

        authenticationEntryPoint.commence(request, response, authException);

        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), eq(UNAUTHORIZED_MESSAGE_ERROR));
    }
}