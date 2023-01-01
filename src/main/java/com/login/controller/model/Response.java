package com.login.controller.model;

import lombok.Data;

import java.util.List;

@Data
public class Response {
    private String token;
    private List<String> roles;
}
