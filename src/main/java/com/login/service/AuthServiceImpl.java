package com.login.service;

import com.login.controller.model.Request;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthServiceImpl implements AuthService {
    @Override
    public boolean isLoggedIn(User user) {
        return user.getUsername().equals("user") && user.getPassword().equals("password");
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return null;
    }

    @Override
    @Transactional
    public void saveUser(Request request) {

    }


}
