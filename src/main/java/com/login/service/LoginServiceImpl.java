package com.login.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

@Service
public class LoginServiceImpl implements LoginService {
    @Override
    public boolean isLoggedIn(User user) {
        return user.getUsername().equals("user") && user.getPassword().equals("password");
    }
}
