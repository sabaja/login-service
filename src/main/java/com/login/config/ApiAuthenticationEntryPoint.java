package com.login.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Invece di attivare il processo di autenticazione reindirizzando a una pagina di login quando un client richiede una risorsa protetta,
 * il server REST autentica tutte le richieste utilizzando i dati disponibili nella richiesta stessa, ovvero il token JWT in questo caso.
 * Se tale autenticazione non riesce, il reindirizzamento non ha senso.
 * L'API REST invia semplicemente una risposta HTTP con codice 401 Non autorizzato e i client dovrebbero sapere cosa fare.
 * Questa classe restituisce semplicemente il codice di risposta HTTP 401 Non autorizzato quando l'autenticazione non riesce,
 * sovrascrivendo il reindirizzamento predefinito di Spring.
 */
@Component
public class ApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

    public static final String UNAUTHORIZED_MESSAGE_ERROR = "Unauthorized";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, UNAUTHORIZED_MESSAGE_ERROR);
    }
}
