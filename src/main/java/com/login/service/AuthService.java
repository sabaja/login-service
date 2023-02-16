package com.login.service;

import com.login.model.AuthenticationRequest;
import com.login.model.AuthenticationResponse;

public interface AuthService {

    AuthenticationResponse generateJwtToken(AuthenticationRequest request);

    void signup(AuthenticationRequest request);
}
