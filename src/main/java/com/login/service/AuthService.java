package com.login.service;

import com.login.controller.model.Request;
import com.login.controller.model.Response;

public interface AuthService {

    Response generateJwtToken(Request request);

    void signup(Request request);
}
