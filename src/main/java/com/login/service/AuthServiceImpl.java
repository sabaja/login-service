package com.login.service;

import com.login.controller.model.Request;
import com.login.controller.model.Response;
import com.login.exception.DisabledUserException;
import com.login.exception.InvalidUserCredentialsException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@Service
public class AuthServiceImpl implements AuthService {

    private final JwtUtilService jwtUtilService;
    private final AuthenticationManager authenticationManager;

    @Override
    public Response generateJwtToken(Request request) {
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUserName(), request.getUserPwd()));
        } catch (DisabledException e) {
            throw new DisabledUserException("User Inactive");
        } catch (BadCredentialsException e) {
            throw new InvalidUserCredentialsException("Invalid Credentials");
        }

        final UserDetails userDetails = jwtUtilService.loadUserByUsername(request.getUserName());
        final String token = jwtUtilService.generateToken(authentication, userDetails);
        final List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return createResponse(token, roles);
    }

    @Override
    public void signup(Request request) {
        jwtUtilService.saveUser(request);
    }

    private Response createResponse(String token, List<String> roles) {
        final Response response = new Response();
        response.setToken(token);
        response.setRoles(roles);
        return response;
    }
}
