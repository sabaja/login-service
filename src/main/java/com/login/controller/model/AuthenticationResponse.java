package com.login.controller.model;

import lombok.Data;

import java.util.List;

@Data
public class AuthenticationResponse {
    private String token;
    private List<String> roles;
}
