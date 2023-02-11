package com.login.controller;

import com.login.controller.model.AuthenticationRequest;
import com.login.controller.model.AuthenticationResponse;
import com.login.service.AuthService;
import com.login.service.JwtUtilService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Slf4j
@RequiredArgsConstructor
@RestController
@CrossOrigin(value = "http://localhost:4200")
@RequestMapping("/auth")
public class AuthController {


    private final JwtUtilService jwtUtilService;
    private final AuthService authService;

    //    https://www.baeldung.com/spring-security-login-angular
    @GetMapping("/authenticated")
    public boolean isLogged(@RequestBody User user) {
        return jwtUtilService.isAuthenticated();
    }

    @GetMapping("/user")
    public Principal user(Principal user) {
        return user;
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthenticationResponse> signin(@RequestBody AuthenticationRequest request) {
        final AuthenticationResponse authenticationResponse = this.authService.generateJwtToken(request);
        return ResponseEntity.ok(authenticationResponse);
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody AuthenticationRequest request) {
        this.authService.signup(request);
        return new ResponseEntity<>("User succesfully registered", HttpStatus.OK);
    }
}
