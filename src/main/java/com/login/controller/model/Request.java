package com.login.controller.model;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

@Data
public class Request implements Serializable {
    private String userName;
    private String userPwd;
    private List<String> roles;
}
