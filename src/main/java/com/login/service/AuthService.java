package com.login.service;

import com.login.controller.model.AuthenticationRequest;
import com.login.controller.model.AuthenticationResponse;

public interface AuthService {

    AuthenticationResponse generateJwtToken(AuthenticationRequest request);

    void signup(AuthenticationRequest request);
}
