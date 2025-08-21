package es.in2.issuer.backend.backoffice.infrastructure.config.security.exception;

import org.springframework.security.core.AuthenticationException;

public class ParseAuthenticationException extends AuthenticationException {

    public ParseAuthenticationException(String msg) {
        super(msg);
    }

    public ParseAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
