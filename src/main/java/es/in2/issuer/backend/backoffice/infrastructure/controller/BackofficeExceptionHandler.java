package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.exception.*;
import es.in2.issuer.backend.backoffice.domain.util.BackofficeErrorTypes;
import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

// todo marke recursive
@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class BackofficeExceptionHandler {

    private final ErrorResponseFactory errors;

    @ExceptionHandler(AuthenticSourcesUserParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleAuthenticSourcesUserParsingException(
            AuthenticSourcesUserParsingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Authentic sources user parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal authentic-sources user parsing error occurred."
        );
    }

    @ExceptionHandler(TemplateReadException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleTemplateReadException(
            TemplateReadException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                BackofficeErrorTypes.TEMPLATE_READ_ERROR.getCode(),
                "Template read error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal template read error occurred."
        );
    }

    @ExceptionHandler(OrganizationIdentifierMismatchException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleOrganizationIdentifierMismatchException(
            OrganizationIdentifierMismatchException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                BackofficeErrorTypes.ORGANIZATION_ID_MISMATCH.getCode(),
                "Unauthorized",
                HttpStatus.FORBIDDEN,
                "Organization identifier mismatch"
        );
    }

    @ExceptionHandler(NoSuchEntityException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoSuchEntityException(
            NoSuchEntityException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                BackofficeErrorTypes.NO_SUCH_ENTITY.getCode(),
                "Not Found",
                HttpStatus.NOT_FOUND,
                "Requested entity was not found"
        );
    }

    @ExceptionHandler(MissingRequiredDataException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleMissingRequiredDataException(
            MissingRequiredDataException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                BackofficeErrorTypes.MISSING_REQUIRED_DATA.getCode(),
                "Bad Request",
                HttpStatus.BAD_REQUEST,
                "Missing required data"
        );
    }

    @ExceptionHandler(InvalidSignatureConfigurationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidSignatureConfigurationException(
            InvalidSignatureConfigurationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                BackofficeErrorTypes.INVALID_SIGNATURE_CONFIGURATION.getCode(),
                "Bad Request",
                HttpStatus.BAD_REQUEST,
                "Invalid signature configuration"
        );
    }

}
