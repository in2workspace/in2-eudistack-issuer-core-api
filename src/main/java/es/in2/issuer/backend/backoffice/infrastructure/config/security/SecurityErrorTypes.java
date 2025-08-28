package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum SecurityErrorTypes {

    DEFAULT_AUTH("authentication_error"),
    DEFAULT_ACCESS("authorization_error"),
    INVALID_TOKEN("invalid_token");

    private final String code;

}
