package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum SecurityErrorTypes {

    DEFAULT_AUTH("authentication_error"),
    DEFAULT_ACCESS("authorization_error"),
    INVALID_TOKEN("invalid_token"),
    CSRF_MISSING("csrf_missing"),
    CSRF_INVALID("csrf_missing");

    private final String code;

}
