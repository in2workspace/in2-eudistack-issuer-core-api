package es.in2.issuer.backend.backoffice.infrastructure.controller;


import es.in2.issuer.backend.backoffice.domain.exception.*;
import es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.NoSuchElementException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CredentialTypeUnsupportedException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> handleCredentialTypeUnsupported(Exception ex) {
        String description = "The given credential type is not supported";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.UNSUPPORTED_CREDENTIAL_TYPE);
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> handleNoSuchElementException(NoSuchElementException ex) {
        String description = "The requested resource was not found";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.NOT_FOUND_RESOURCE);
    }

    @ExceptionHandler(ExpiredCacheException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleExpiredCacheException(Exception ex) {
        String description = "The given credential ID does not match with any credentials";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.VC_DOES_NOT_EXIST);
    }

    @ExceptionHandler(ExpiredPreAuthorizedCodeException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> expiredPreAuthorizedCode(Exception ex) {
        String description = "The pre-authorized code has expired, has been used, or does not exist.";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.EXPIRED_PRE_AUTHORIZED_CODE);
    }

    @ExceptionHandler(InvalidOrMissingProofException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> handleInvalidOrMissingProof(Exception ex) {
        String description = "Credential Request did not contain a proof, or proof was invalid, " +
                "i.e. it was not bound to a Credential Issuer provided nonce";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.INVALID_OR_MISSING_PROOF);
    }

    @ExceptionHandler(InvalidTokenException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> handleInvalidToken(Exception ex) {
        String description = "Credential Request contains the wrong Access Token or the Access Token is missing";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.INVALID_TOKEN);
    }

    @ExceptionHandler(UserDoesNotExistException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> handleUserDoesNotExistException(Exception ex) {
        String description = "User does not exist";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.USER_DOES_NOT_EXIST);
    }

    @ExceptionHandler(VcTemplateDoesNotExistException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> vcTemplateDoesNotExist(Exception ex) {
        String description = "The given template name is not supported";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST);
    }

    @ExceptionHandler(ParseException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleParseException(ParseException ex) {
        String description = "An error occurred while parsing the credential data";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.PARSING_CREDENTIAL_ERROR);
    }

    @ExceptionHandler(Base45Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleBase45Exception(Base45Exception ex) {
        String description = "An error occurred while decoding the Base45-encoded data";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.BASE_45_ERROR);
    }

    @ExceptionHandler(CreateDateException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleCreateDateException(CreateDateException ex) {
        String description = "An error occurred while creating the credential issuance date";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.CREATE_DATE_ERROR);
    }

    @ExceptionHandler(SignedDataParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleSignedDataParsingException(SignedDataParsingException ex) {
        String description = "An error occurred while parsing the signed credential data";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.SIGNED_DATA_PARSING_ERROR);
    }

    @ExceptionHandler(AuthenticSourcesUserParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleSignedDataParsingException(AuthenticSourcesUserParsingException ex) {
        String description = "An error occurred while parsing the authentic sources user information";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.AUTHENTIC_SOURCES_USER_PARSING_ERROR);
    }

    @ExceptionHandler(ParseCredentialJsonException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleParseCredentialJsonException(ParseCredentialJsonException ex) {
        String description = "An error occurred while parsing the credential JSON data";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.PARSE_CREDENTIAL_JSON_ERROR);
    }

    @ExceptionHandler(TemplateReadException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleTemplateReadException(TemplateReadException ex) {
        String description = "An error occurred while reading the credential template";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.TEMPLATE_READ_ERROR);
    }

    @ExceptionHandler(ProofValidationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleProofValidationException(ProofValidationException ex) {
        String description = "An error occurred during the validation of the credential proof";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.PROOF_VALIDATION_ERROR);
    }

    @ExceptionHandler(NoCredentialFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> handleNoCredentialFoundException(NoCredentialFoundException ex) {
        String description = "No credential was found matching the request";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.CREDENTIAL_NOT_FOUND);
    }

    @ExceptionHandler(PreAuthorizationCodeGetException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handlePreAuthorizationCodeGetException(PreAuthorizationCodeGetException ex) {
        String description = "An error occurred while retrieving the pre-authorization code";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.PRE_AUTHORIZATION_CODE_GET_ERROR);
    }

    @ExceptionHandler(CredentialOfferNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<CredentialErrorResponse> handleCustomCredentialOfferNotFoundException(CredentialOfferNotFoundException ex) {
        String description = "The requested credential offer was not found";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.CREDENTIAL_OFFER_NOT_FOUND);
    }

    @ExceptionHandler(CredentialAlreadyIssuedException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<CredentialErrorResponse> handleCredentialAlreadyIssuedException(CredentialAlreadyIssuedException ex) {
        String description = "The credential has already been issued and cannot be issued again";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.CREDENTIAL_ALREADY_ISSUED);
    }

    @ExceptionHandler(OperationNotSupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleOperationNotSupportedException(Exception ex) {
        String description = "The given operation is not supported";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.OPERATION_NOT_SUPPORTED);
    }

    @ExceptionHandler(JWTVerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<CredentialErrorResponse> handleJWTVerificationException(JWTVerificationException ex) {
        String description = "Error verification the JWT";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.JWT_VERIFICATION_ERROR);
    }

    @ExceptionHandler(ResponseUriException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<CredentialErrorResponse> handleResponseUriException(Exception ex) {
        String description = "Request to response uri failed";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.RESPONSE_URI_ERROR);
    }

    @ExceptionHandler(InsufficientPermissionException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<CredentialErrorResponse> handleInsufficientPermissionException(Exception ex) {
        String description = "The client who made the issuance request do not have the required permissions";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.INSUFFICIENT_PERMISSION);
    }

    @ExceptionHandler(EmailCommunicationException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Mono<CredentialErrorResponse> handleEmailCommunicationException(EmailCommunicationException ex) {
        String description = "An error occurred while sending the email communication";
        return getCredentialErrorResponse(ex, description, CredentialResponseErrorCodes.EMAIL_COMMUNICATION_ERROR);
    }

    private Mono<CredentialErrorResponse> getCredentialErrorResponse(
            Exception exception,
            String fallbackDescription,
            String credentialResponseErrorCode) {
        return Mono.fromSupplier(() -> new CredentialErrorResponse(
                credentialResponseErrorCode,
                getDescription(exception, fallbackDescription)
        ));
    }

    private String getDescription(Exception exception, String fallbackDescription) {
        String exceptionMessage = exception.getMessage();
        if (exceptionMessage != null && !exceptionMessage.isBlank()) {
            log.error("{}: {}", exception.getClass().getSimpleName(), exceptionMessage);
            return exceptionMessage;
        }
        return fallbackDescription;
    }
}
