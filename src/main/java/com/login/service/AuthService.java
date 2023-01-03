package com.login.service;

import com.login.controller.model.Request;

public interface AuthService {


    boolean isAuthenticated();

    void saveUser(Request request);
}
