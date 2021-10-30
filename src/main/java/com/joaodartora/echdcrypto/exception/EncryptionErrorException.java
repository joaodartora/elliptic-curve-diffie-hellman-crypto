package com.joaodartora.echdcrypto.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.INTERNAL_SERVER_ERROR, reason = "Error encrypting message")
public class EncryptionErrorException extends RuntimeException {

    public EncryptionErrorException(Exception e) {
        super(e);
    }
}
