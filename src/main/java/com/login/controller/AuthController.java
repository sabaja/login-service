package com.login.controller;

import com.login.service.AuthService;
import com.login.service.JwtUtilService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService loginService;

    @Autowired
    private JwtUtilService jwtUtilService;

    //    https://www.baeldung.com/spring-security-login-angular
    @GetMapping("/authenticated")
    public boolean isLogged(@RequestBody User user) {
        return loginService.isAuthenticated();
    }

    @GetMapping("/user")
    public Principal user(Principal user) {
        return user;
    }

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/token")
    public ResponseEntity<String> testToken() {
        UserDetails user = createUserDetails();
        final String body = this.jwtUtilService.generateToken(user);
        return ResponseEntity.ok(body);
    }

    private UserDetails createUserDetails() {
        return new User("USER", "password", List.of(new SimpleGrantedAuthority("USER_ROLE")));
    }
}
