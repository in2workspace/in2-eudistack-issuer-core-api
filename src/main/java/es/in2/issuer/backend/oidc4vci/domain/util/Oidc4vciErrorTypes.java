package es.in2.issuer.backend.oidc4vci.domain.util;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

//todo use when there are error types specific from Oidc4vci module
@Getter
@RequiredArgsConstructor
public enum Oidc4vciErrorTypes {

    ;

    private final String code;

}
