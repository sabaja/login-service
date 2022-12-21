package com.login.controller;

import com.login.controller.model.CourseUser;
import com.login.service.JwtUtilService;
import com.login.service.LoginService;
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
@RequestMapping("/courses/login")
public class LoginController {

    @Autowired
    private LoginService loginService;

    @Autowired
    private JwtUtilService jwtUtilService;

    //    https://www.baeldung.com/spring-security-login-angular
    @GetMapping()
    public boolean login(@RequestBody User user) {
        return loginService.isLoggedIn(user);
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
        return ResponseEntity.ok(this.jwtUtilService.generateToken(user));
    }

    private UserDetails createUserDetails() {
        return new CourseUser("USER", "password", List.of(new SimpleGrantedAuthority("USER_ROLE")));
    }
}
