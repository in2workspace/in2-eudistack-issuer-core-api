package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class Oidc4vciExceptionHandler {
    private final ErrorResponseFactory errors;

    //todo remove when GlobalErrorTypes are used in more than one module
    @SuppressWarnings("unused")
    private static final Class<?> __arch_touch_global_error_types =
            GlobalErrorTypes.class;
}
