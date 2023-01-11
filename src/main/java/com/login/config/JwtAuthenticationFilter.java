package com.login.config;

import com.login.exception.JwtTokenMissingException;
import com.login.service.JwtUtilService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;


/**
 * {@code JwtAuthenticationFilter} viene invocata nel momento venga richiesta una risorsa protetta.
 * Inoltre la classe {@link  OncePerRequestFilter} estesa da {@code JwtAuthenticationFilter}  garantisce un'istanza unica 
 * per una singola esecuzione per invio di richiesta, su qualsiasi servlet container. 
 * A partire da Servlet 3.0, un filtro può essere richiamato come parte di un invio REQUEST o ASYNC che si verifica in thread separati.
 */
@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private static final String PREFIX_HEADER_TOKEN = "Bearer";


    private final JwtUtilService jwtUtilService;

    public JwtAuthenticationFilter(@Lazy JwtUtilService jwtUtilService) {
        this.jwtUtilService = jwtUtilService;
    }

    /*
        https://www.youtube.com/watch?v=b9O9NI-RJ3o 45:50
        https://www.programcreek.com/java-api-examples/?code=TANGKUO%2FHIS%2FHIS-master%2Fhis-cloud%2Fhis-cloud-zuul%2Fsrc%2Fmain%2Fjava%2Fcom%2Fneu%2Fhis%2Fcloud%2Fzuul%2Fcomponent%2FJwtAuthenticationTokenFilter.java
        */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader(AUTHORIZATION);

        // If the header is null or does not contain the Bearer, it continues doing nothing
//        if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, PREFIX_HEADER_TOKEN)) {
//            filterChain.doFilter(request, response);
//            return;
//        }
        if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, PREFIX_HEADER_TOKEN)) {
            throw new JwtTokenMissingException("No JWT token found in the request headers");
        }
        final String jwtToken = authHeader.substring(PREFIX_HEADER_TOKEN.length() + 1);
        final String userEmail = jwtUtilService.getUsername(jwtToken);

        if (StringUtils.isNotBlank(userEmail)) {
            final UserDetails userDetails = jwtUtilService.loadUserByUsername(userEmail);

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
