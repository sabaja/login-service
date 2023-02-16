package com.login.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

// https://www.javaguides.net/2021/04/spring-boot-dto-validation-example.html
@Data
public class AuthenticationRequest implements Serializable {

    @NotBlank
    private String userName;

    @NotEmpty
    @Size(min = 8, message = "password should have at least 8 characters")
    private String userPwd;
    private List<String> roles;
}
