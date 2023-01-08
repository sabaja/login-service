package com.login.controller;

import com.login.controller.model.Request;
import com.login.controller.model.Response;
import com.login.service.AuthService;
import com.login.service.JwtUtilService;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@Slf4j
@RestController
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

    @PostMapping("/signin")
    public ResponseEntity<Response> signin(@RequestBody Request request) {
        final Response response = this.authService.generateJwtToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody Request request) {
        this.authService.signup(request);
        return ResponseEntity.ok(Strings.EMPTY);
    }

    private UserDetails createUserDetails() {
        return new User("USER", "password", List.of(new SimpleGrantedAuthority("USER_ROLE")));
    }
}
