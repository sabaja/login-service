package com.login.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class JwtTokenMalformedException extends ResponseStatusException {

    private static final long serialVersionUID = 1L;

    public JwtTokenMalformedException(String msg) {
        super(HttpStatus.BAD_REQUEST, msg);
    }
}
