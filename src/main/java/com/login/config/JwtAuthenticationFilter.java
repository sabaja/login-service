package com.login.config;

import com.login.service.AuthServiceImpl;
import com.login.service.JwtUtilService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private static final String PREFIX_HEADER_TOKEN = "Bearer";
    private final AuthServiceImpl authService;
    private final JwtUtilService jwtUtilService;

    /*
    https://www.youtube.com/watch?v=b9O9NI-RJ3o 45:50
    https://www.programcreek.com/java-api-examples/?code=TANGKUO%2FHIS%2FHIS-master%2Fhis-cloud%2Fhis-cloud-zuul%2Fsrc%2Fmain%2Fjava%2Fcom%2Fneu%2Fhis%2Fcloud%2Fzuul%2Fcomponent%2FJwtAuthenticationTokenFilter.java
    */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader(AUTHORIZATION);

        // If the header is null or does not contain the Bearer, it continues doing nothing
        if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, PREFIX_HEADER_TOKEN)) {
            filterChain.doFilter(request, response);
        }
        final String jwtToken = authHeader.substring(PREFIX_HEADER_TOKEN.length() + 1);
        final String userEmail = jwtUtilService.getUsername(jwtToken);

        if (StringUtils.isNotBlank(userEmail)) {
            final UserDetails userDetails = authService.loadUserByUsername(userEmail);

            if (Boolean.TRUE.equals(jwtUtilService.validateToken(jwtToken, userDetails))) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                final SecurityContext context = SecurityContextHolder.getContext();

                if (context.getAuthentication() == null) {
                    context.setAuthentication(authToken);
                }
                log.info("authenticated user:{}", userEmail);
            }
        }
        filterChain.doFilter(request, response);
    }
}
