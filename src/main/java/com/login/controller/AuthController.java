package com.login.controller;

import com.login.controller.model.Request;
import com.login.controller.model.Response;
import com.login.service.AuthService;
import com.login.service.JwtUtilService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Slf4j
@RestController
@CrossOrigin(value = "http://localhost:4200")
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private JwtUtilService jwtUtilService;
    @Autowired
    private AuthService authService;

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
    public ResponseEntity<Response> signin(@RequestBody Request request) {
        final Response response = this.authService.generateJwtToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup")
    public ResponseEntity<Boolean> signup(@RequestBody Request request) {
        this.authService.signup(request);
        return ResponseEntity.ok(Boolean.TRUE);
    }
}
