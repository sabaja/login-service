package com.login.controller;

import com.login.service.LoginService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("courses")
public class LoginController {

    @Autowired
    private LoginService loginService;

    //    https://www.baeldung.com/spring-security-login-angular
    @GetMapping("/login")
    public boolean login(@RequestBody User user) {
        return loginService.isLoggedIn(user);
    }


}
