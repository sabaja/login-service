package com.login.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class JwtTokenMissingException extends ResponseStatusException {

    private static final long serialVersionUID = 1L;

    public JwtTokenMissingException(String msg) {
        super(HttpStatus.UNAUTHORIZED, msg);
    }
}
