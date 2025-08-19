package es.in2.issuer.backend.backoffice.infrastructure.controller;


import es.in2.issuer.backend.backoffice.domain.exception.*;
import es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialErrorResponse;
import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.NoSuchElementException;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.ERROR_LOG_FORMAT;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CredentialTypeUnsupportedException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleCredentialTypeUnsupported(
            CredentialTypeUnsupportedException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.UNSUPPORTED_CREDENTIAL_TYPE,
                "Unsupported credential type",
                HttpStatus.NOT_FOUND,
                "The given credential type is not supported"
        );
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoSuchElementException(
            NoSuchElementException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.NO_SUCH_ELEMENT,
                "Resource not found",
                HttpStatus.NOT_FOUND,
                "The requested resource was not found"
        );
    }


    @ExceptionHandler(ExpiredCacheException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleExpiredCache(
            ExpiredCacheException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.VC_DOES_NOT_EXIST,
                "Credential does not exist",
                HttpStatus.BAD_REQUEST,
                "The given credential ID does not match with any credentials"
        );
    }

    @ExceptionHandler(ExpiredPreAuthorizedCodeException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleExpiredPreAuthorizedCode(
            ExpiredPreAuthorizedCodeException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.EXPIRED_PRE_AUTHORIZED_CODE,
                "Expired pre-authorized code",
                HttpStatus.NOT_FOUND,
                "The pre-authorized code has expired, has been used, or does not exist."
        );
    }


    @ExceptionHandler(InvalidOrMissingProofException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleInvalidOrMissingProof(
            InvalidOrMissingProofException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.INVALID_OR_MISSING_PROOF,
                "Invalid or missing proof",
                HttpStatus.NOT_FOUND,
                "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce."
        );
    }


    @ExceptionHandler(InvalidTokenException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleInvalidToken(
            InvalidTokenException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.INVALID_TOKEN,
                "Invalid token",
                HttpStatus.NOT_FOUND,
                "Credential Request contains the wrong Access Token or the Access Token is missing"
        );
    }


    @ExceptionHandler(UserDoesNotExistException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleUserDoesNotExist(
            UserDoesNotExistException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.USER_DOES_NOT_EXIST,
                "User does not exist",
                HttpStatus.NOT_FOUND,
                "User does not exist"
        );
    }


    @ExceptionHandler(VcTemplateDoesNotExistException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleVcTemplateDoesNotExist(
            VcTemplateDoesNotExistException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST,
                "VC template does not exist",
                HttpStatus.NOT_FOUND,
                "The given template name is not supported"
        );
    }

    @ExceptionHandler(ParseException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleParseException(
            ParseException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                // todo
                "parse_error",
                "Parse error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal parsing error occurred."
        );
    }

    @ExceptionHandler(Base45Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleBase45Exception(
            Base45Exception ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                // todo --parse_error?
                "base45_decode_error",
                "Base45 decoding error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal Base45 decoding error occurred."
        );
    }

    @ExceptionHandler(CreateDateException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleCreateDateException(
            CreateDateException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                // todo --parse_error?
                "create_date_error",
                "Create date error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal date creation error occurred."
        );
    }

    @ExceptionHandler(SignedDataParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleSignedDataParsingException(
            SignedDataParsingException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                // todo parse_error?
                "signed_data_parse_error",
                "Signed data parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal signed data parsing error occurred."
        );
    }


    @ExceptionHandler(AuthenticSourcesUserParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleAuthenticSourcesUserParsingException(
            AuthenticSourcesUserParsingException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "authentic_sources_user_parsing_error",
                "Authentic sources user parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal authentic-sources user parsing error occurred."
        );
    }


    @ExceptionHandler(ParseCredentialJsonException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleParseCredentialJsonException(
            ParseCredentialJsonException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "parse_credential_json_error",
                "Credential JSON parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal credential JSON parsing error occurred."
        );
    }


    @ExceptionHandler(TemplateReadException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleTemplateReadException(
            TemplateReadException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "template_read_error",
                "Template read error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal template read error occurred."
        );
    }


    @ExceptionHandler(ProofValidationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleProofValidationException(
            ProofValidationException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "proof_validation_error",
                "Proof validation error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal proof validation error occurred."
        );
    }


    @ExceptionHandler(NoCredentialFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoCredentialFoundException(
            NoCredentialFoundException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "no_credential_found",
                "Credential not found",
                HttpStatus.NOT_FOUND,
                "No credential found."
        );
    }

    @ExceptionHandler(PreAuthorizationCodeGetException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handlePreAuthorizationCodeGetException(
            PreAuthorizationCodeGetException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "pre_authorization_code_get_exception",
                "Pre-authorization code retrieval error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to retrieve pre-authorization code."
        );
    }


    @ExceptionHandler(CredentialOfferNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleCredentialOfferNotFoundException(
            CredentialOfferNotFoundException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "credential_offer_not_found",
                "Credential offer not found",
                HttpStatus.NOT_FOUND,
                "Credential offer not found."
        );
    }


    @ExceptionHandler(CredentialAlreadyIssuedException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleCredentialAlreadyIssuedException(
            CredentialAlreadyIssuedException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "credential_already_issued",
                "Credential already issued",
                HttpStatus.CONFLICT,
                "The credential has already been issued."
        );
    }

    @ExceptionHandler(OperationNotSupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleOperationNotSupportedException(
            OperationNotSupportedException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.OPERATION_NOT_SUPPORTED,
                "Operation not supported",
                HttpStatus.BAD_REQUEST,
                "The given operation is not supported"
        );
    }


    @ExceptionHandler(JWTVerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleJWTVerificationException(
            JWTVerificationException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "jwt_verification_error",
                "JWT verification failed",
                HttpStatus.UNAUTHORIZED,
                "JWT verification failed."
        );
    }

    @ExceptionHandler(ResponseUriException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleResponseUriException(
            ResponseUriException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.RESPONSE_URI_ERROR,
                "Response URI error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Request to response URI failed"
        );
    }


    @ExceptionHandler(FormatUnsupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleFormatUnsupportedException(
            FormatUnsupportedException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.FORMAT_IS_NOT_SUPPORTED,
                "Format not supported",
                HttpStatus.BAD_REQUEST,
                "Format is not supported"
        );
    }


    @ExceptionHandler(InsufficientPermissionException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleInsufficientPermissionException(
            InsufficientPermissionException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.INSUFFICIENT_PERMISSION,
                "Insufficient permission",
                HttpStatus.FORBIDDEN,
                "The client who made the issuance request do not have the required permissions"
        );
    }


    @ExceptionHandler(UnauthorizedRoleException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleUnauthorizedRoleException(
            UnauthorizedRoleException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "unauthorized_role",
                "Unauthorized role",
                HttpStatus.UNAUTHORIZED,
                "The user role is not authorized to perform this action"
        );
    }

    @ExceptionHandler(EmailCommunicationException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Mono<GlobalErrorMessage> handleEmailCommunicationException(
            EmailCommunicationException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "email_communication_error",
                "Email communication error",
                HttpStatus.SERVICE_UNAVAILABLE,
                "Email communication failed"
        );
    }

    @ExceptionHandler(MissingIdTokenHeaderException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleMissingIdTokenHeaderException(
            MissingIdTokenHeaderException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.MISSING_HEADER,
                "Missing header",
                HttpStatus.BAD_REQUEST,
                "The X-ID-TOKEN header is missing, this header is needed to issue a Verifiable Certification"
        );
    }


    @ExceptionHandler(OrganizationIdentifierMismatchException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleOrganizationIdentifierMismatchException(
            OrganizationIdentifierMismatchException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                "organization_id_mismatch_error",
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
        return handleWith(
                ex, request,
                "no_such_entity",
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
        return handleWith(
                ex, request,
                "missing_required_data_error",
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
        return handleWith(
                ex, request,
                "invalid_signature_configuration_error",
                "Bad Request",
                HttpStatus.BAD_REQUEST,
                "Invalid signature configuration"
        );
    }


    @ExceptionHandler(SadException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Mono<GlobalErrorMessage> handleSadError(
            SadException ex,
            ServerHttpRequest request
    ) {
        return handleWith(
                ex, request,
                CredentialResponseErrorCodes.SAD_ERROR,
                "SAD error",
                HttpStatus.BAD_GATEWAY,
                "An upstream SAD error occurred"
        );
    }


    private Mono<GlobalErrorMessage> handleWith(
            Exception ex,
            ServerHttpRequest request,
            String type,
            String title,
            HttpStatus status,
            String fallbackDetail
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return Mono.just(buildError(type, title, status, detail, ex, request));
    }

    private String resolveDetail(Exception ex, String fallback) {
        String msg = ex.getMessage();
        return (msg == null || msg.isBlank()) ? fallback : msg;
    }

    private GlobalErrorMessage buildError(
            String type,
            String title,
            HttpStatus httpStatus,
            String detail,
            Exception ex,
            ServerHttpRequest request
    ) {
        String instance = UUID.randomUUID().toString();
        RequestPath path = request.getPath();

        log.error(ERROR_LOG_FORMAT, instance, path, httpStatus.value(), ex.getClass(), detail);

        return new GlobalErrorMessage(
                type,
                title,
                httpStatus.value(),
                detail,
                instance
        );
    }

}
