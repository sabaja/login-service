package com.login.service;

import org.springframework.security.core.userdetails.User;

public interface LoginService {
    boolean isLoggedIn(User user);
}
