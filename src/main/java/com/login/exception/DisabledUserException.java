package com.login.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class DisabledUserException extends ResponseStatusException {

    private static final long serialVersionUID = 1L;

    public DisabledUserException(String msg) {
        super(HttpStatus.UNAUTHORIZED, msg);
    }
}