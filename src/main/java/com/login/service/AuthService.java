package com.login.service;

import com.login.controller.model.Request;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface AuthService {
    boolean isLoggedIn(User user);

    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

    public void saveUser(Request request);
}
