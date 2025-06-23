package es.in2.issuer.backend.backoffice.infrastructure.controller;


import es.in2.issuer.backend.backoffice.domain.exception.*;
import es.in2.issuer.backend.backoffice.domain.model.dtos.GlobalErrorMessage;
import es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.context.request.WebRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.NoSuchElementException;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {
    private GlobalExceptionHandler globalExceptionHandler;

    @BeforeEach
    void setUp() {
        globalExceptionHandler = new GlobalExceptionHandler();
        WebRequest mockWebRequest = mock(WebRequest.class);
        when(mockWebRequest.getDescription(false)).thenReturn("WebRequestDescription");
    }

    @Test
    void handleCredentialTypeUnsupported() {
        CredentialTypeUnsupportedException exception = new CredentialTypeUnsupportedException("The given credential type is not supported");

        Mono<ResponseEntity<CredentialErrorResponse>> result = globalExceptionHandler.handleCredentialTypeUnsupported(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.UNSUPPORTED_CREDENTIAL_TYPE, responseEntity.getBody().error());
                    assertEquals("The given credential type is not supported", responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleNoSuchElement() {
        NoSuchElementException exception = new NoSuchElementException();

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleNoSuchElementException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleExpiredCache() {
        ExpiredCacheException exception = new ExpiredCacheException("The given credential ID does not match with any credentials");

        Mono<ResponseEntity<CredentialErrorResponse>> result = globalExceptionHandler.handleExpiredCacheException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.VC_DOES_NOT_EXIST, responseEntity.getBody().error());
                    assertEquals("The given credential ID does not match with any credentials", responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleExpiredPreAuthorizedCode() {
        ExpiredPreAuthorizedCodeException exception = new ExpiredPreAuthorizedCodeException("Error message");

        Mono<ResponseEntity<CredentialErrorResponse>> result = globalExceptionHandler.expiredPreAuthorizedCode(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.EXPIRED_PRE_AUTHORIZED_CODE, responseEntity.getBody().error());
                    assertEquals("The pre-authorized code has expired, has been used, or does not exist.", responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleInvalidOrMissingProof() {
        InvalidOrMissingProofException exception = new InvalidOrMissingProofException("Error message");

        Mono<ResponseEntity<CredentialErrorResponse>> result = globalExceptionHandler.handleInvalidOrMissingProof(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.INVALID_OR_MISSING_PROOF, responseEntity.getBody().error());
                    assertEquals("Credential Request did not contain a proof, or proof was invalid, " +
                            "i.e. it was not bound to a Credential Issuer provided nonce", responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleInvalidToken() {
        InvalidTokenException exception = new InvalidTokenException();

        Mono<ResponseEntity<CredentialErrorResponse>> result = globalExceptionHandler.handleInvalidToken(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.INVALID_TOKEN, responseEntity.getBody().error());
                    assertEquals("The request contains the wrong Access Token or the Access Token is missing", responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleUserDoesNotExist() {
        UserDoesNotExistException exception = new UserDoesNotExistException(null);

        Mono<ResponseEntity<CredentialErrorResponse>> result = globalExceptionHandler.handleUserDoesNotExistException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.USER_DOES_NOT_EXIST, responseEntity.getBody().error());
                    assertEquals("User does not exist", responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleUserDoesNotExistException_withMessage() {
        String errorMessage = "Error message for testing";
        UserDoesNotExistException userDoesNotExistException = new UserDoesNotExistException(errorMessage);

        Mono<ResponseEntity<CredentialErrorResponse>> responseEntityMono = globalExceptionHandler.handleUserDoesNotExistException(userDoesNotExistException);

        StepVerifier.create(responseEntityMono)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.USER_DOES_NOT_EXIST, responseEntity.getBody().error());
                    assertEquals(errorMessage, responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleVcTemplateDoesNotExist() {
        VcTemplateDoesNotExistException exception = new VcTemplateDoesNotExistException(null);

        Mono<ResponseEntity<CredentialErrorResponse>> result = globalExceptionHandler.vcTemplateDoesNotExist(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST, responseEntity.getBody().error());
                    assertEquals("The given template name is not supported", responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleVcTemplateDoesNotExist_withMessage() {
        String errorMessage = "Error message for testing";
        VcTemplateDoesNotExistException vcTemplateDoesNotExistException = new VcTemplateDoesNotExistException(errorMessage);

        Mono<ResponseEntity<CredentialErrorResponse>> responseEntityMono = globalExceptionHandler.vcTemplateDoesNotExist(vcTemplateDoesNotExistException);

        StepVerifier.create(responseEntityMono)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST, responseEntity.getBody().error());
                    assertEquals(errorMessage, responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleParseException() {
        ParseException exception = new ParseException("Error message", 213);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleParseException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleBase45Exception() {
        Base45Exception exception = new Base45Exception(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleBase45Exception(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleCreateDate() {
        CreateDateException exception = new CreateDateException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleCreateDateException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleSignedDataParsing() {
        SignedDataParsingException exception = new SignedDataParsingException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleSignedDataParsingException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleAuthenticSourcesUserParsing() {
        AuthenticSourcesUserParsingException exception = new AuthenticSourcesUserParsingException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleSignedDataParsingException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleParseCredentialJsonException() {
        ParseCredentialJsonException exception = new ParseCredentialJsonException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleParseCredentialJsonException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleTemplateReadException() {
        TemplateReadException exception = new TemplateReadException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleTemplateReadException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleProofValidationException() {
        ProofValidationException exception = new ProofValidationException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleProofValidationException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleNoCredentialFoundException() {
        NoCredentialFoundException exception = new NoCredentialFoundException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleNoCredentialFoundException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handlePreAuthorizationCodeGetException() {
        PreAuthorizationCodeGetException exception = new PreAuthorizationCodeGetException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handlePreAuthorizationCodeGetException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleCustomCredentialOfferNotFoundException() {
        CredentialOfferNotFoundException exception = new CredentialOfferNotFoundException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleCustomCredentialOfferNotFoundException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleOperationNotSupportedException_withMessage() {
        String errorMessage = "Error message for testing";
        OperationNotSupportedException operationNotSupportedException = new OperationNotSupportedException(errorMessage);

        Mono<ResponseEntity<CredentialErrorResponse>> responseEntityMono = globalExceptionHandler.handleOperationNotSupportedException(operationNotSupportedException);

        StepVerifier.create(responseEntityMono)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.OPERATION_NOT_SUPPORTED, responseEntity.getBody().error());
                    assertEquals(errorMessage, responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleJWTVerificationException() {
        JWTVerificationException exception = new JWTVerificationException("message");

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleJWTVerificationException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.UNAUTHORIZED, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleResponseUriException_withMessage() {
        String errorMessage = "Error message for testing";
        ResponseUriException responseUriException = new ResponseUriException(errorMessage);

        Mono<ResponseEntity<CredentialErrorResponse>> responseEntityMono = globalExceptionHandler.handleResponseUriException(responseUriException);

        StepVerifier.create(responseEntityMono)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.RESPONSE_URI_ERROR, responseEntity.getBody().error());
                    assertEquals(errorMessage, responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleFormatUnsupportedException_withMessage() {
        String errorMessage = "Error message for testing";
        FormatUnsupportedException formatUnsupportedException = new FormatUnsupportedException(errorMessage);

        Mono<ResponseEntity<CredentialErrorResponse>> responseEntityMono = globalExceptionHandler.handleFormatUnsupportedException(formatUnsupportedException);

        StepVerifier.create(responseEntityMono)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.FORMAT_IS_NOT_SUPPORTED, responseEntity.getBody().error());
                    assertEquals(errorMessage, responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleTrustServiceProviderForCertificationsException_withMessage() {
        String errorMessage = "Error message for testing";
        InsufficientPermissionException insufficientPermissionException = new InsufficientPermissionException(errorMessage);

        Mono<ResponseEntity<CredentialErrorResponse>> responseEntityMono = globalExceptionHandler.handleInsufficientPermissionException(insufficientPermissionException);

        StepVerifier.create(responseEntityMono)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
                    assertNotNull(responseEntity.getBody());
                    assertEquals(CredentialResponseErrorCodes.INSUFFICIENT_PERMISSION, responseEntity.getBody().error());
                    assertEquals(errorMessage, responseEntity.getBody().description());
                })
                .verifyComplete();
    }

    @Test
    void handleUnauthorizedRoleException() {
        String errorMessage = "Error message for testing";
        UnauthorizedRoleException unauthorizedRoleException = new UnauthorizedRoleException(errorMessage);

        Mono<es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage> resultMono =
                globalExceptionHandler.handleUnauthorizedRoleException(unauthorizedRoleException);

        StepVerifier.create(resultMono)
                .assertNext(result -> {
                    assertEquals(HttpStatus.UNAUTHORIZED.value(), result.status());
                    assertNotNull(result.message());
                    assertEquals("UnauthorizedRoleException", result.error());
                })
                .verifyComplete();
    }

    @Test
    void handleCredentialAlreadyIssuedException() {
        CredentialAlreadyIssuedException exception = new CredentialAlreadyIssuedException(null);

        Mono<ResponseEntity<Void>> result = globalExceptionHandler.handleCredentialAlreadyIssuedException(exception);

        StepVerifier.create(result)
                .assertNext(responseEntity -> assertEquals(HttpStatus.CONFLICT, responseEntity.getStatusCode()))
                .verifyComplete();
    }

    @Test
    void handleEmailCommunicationException_withMessage() {
        String errorMessage = "Notification service unavailable";
        EmailCommunicationException exception = new EmailCommunicationException(errorMessage);

        Mono<es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage> result = globalExceptionHandler.handleEmailCommunicationException(exception);

        StepVerifier.create(result)
                .assertNext(globalErrorMessage -> {
                    assertEquals(HttpStatus.SERVICE_UNAVAILABLE.value(), globalErrorMessage.status());
                    assertEquals(errorMessage, globalErrorMessage.message());
                })
                .verifyComplete();
    }

    @Test
    void handleEmailCommunicationException_withoutMessage() {
        EmailCommunicationException exception = new EmailCommunicationException(null);

        Mono<es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage> result = globalExceptionHandler.handleEmailCommunicationException(exception);

        StepVerifier.create(result)
                .assertNext(globalErrorMessage -> {
                    assertEquals(HttpStatus.SERVICE_UNAVAILABLE.value(), globalErrorMessage.status());
                    assertNull(globalErrorMessage.message());
                })
                .verifyComplete();
    }

    @Test
    void handleMissingIdTokenHeaderException_withoutMessage() {
        MissingIdTokenHeaderException ex = new MissingIdTokenHeaderException(null);

        Mono<ResponseEntity<CredentialErrorResponse>> result =
                globalExceptionHandler.handleMissingIdTokenHeaderException(ex);

        StepVerifier.create(result)
                .assertNext(resp -> {
                    assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
                    CredentialErrorResponse body = resp.getBody();
                    assertNotNull(body);
                    assertEquals(CredentialResponseErrorCodes.MISSING_HEADER, body.error());
                    assertEquals(
                            "The X-ID-TOKEN header is missing, this header is needed to issuer a Verifiable Certification",
                            body.description()
                    );
                })
                .verifyComplete();
    }

    @Test
    void handleMissingIdTokenHeaderException_withMessage() {
        String msg = "Custom missing header message";
        MissingIdTokenHeaderException ex = new MissingIdTokenHeaderException(msg);

        Mono<ResponseEntity<CredentialErrorResponse>> result =
                globalExceptionHandler.handleMissingIdTokenHeaderException(ex);

        StepVerifier.create(result)
                .assertNext(resp -> {
                    assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
                    CredentialErrorResponse body = resp.getBody();
                    assertNotNull(body);
                    assertEquals(CredentialResponseErrorCodes.MISSING_HEADER, body.error());
                    assertEquals(msg, body.description());
                })
                .verifyComplete();
    }

    @Test
    void handleOrganizationIdentifierMismatchException() {
        RequestPath mockPath = mock(RequestPath.class);
        when(mockPath.toString()).thenReturn("/org");
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getPath()).thenReturn(mockPath);

        String msg = "Org ID mismatch!";
        OrganizationIdentifierMismatchException ex =
                new OrganizationIdentifierMismatchException(msg);

        Mono<ResponseEntity<GlobalErrorMessage>> result =
                globalExceptionHandler.handleOrganizationIdentifierMismatchException(ex, request);

        StepVerifier.create(result)
                .assertNext(resp -> {
                    assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
                    GlobalErrorMessage er = resp.getBody();
                    assertNotNull(er);
                    assertEquals("Unauthorized", er.type());
                    assertEquals(OrganizationIdentifierMismatchException.class.toString(), er.title());
                    assertEquals(403, er.status());
                    assertEquals(msg, er.detail());
                    assertNotNull(er.instance());
                    assertTrue(Pattern.matches(
                            "[0-9a-fA-F\\-]{36}", er.instance()
                    ));
                })
                .verifyComplete();
    }

    @Test
    void handleNoSuchEntityException() {
        RequestPath mockPath = mock(RequestPath.class);
        when(mockPath.toString()).thenReturn("/nosuch");
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getPath()).thenReturn(mockPath);

        String msg = "Not found!";
        NoSuchEntityException ex = new NoSuchEntityException(msg);

        Mono<ResponseEntity<GlobalErrorMessage>> result =
                globalExceptionHandler.handleNoSuchEntityException(ex, request);

        StepVerifier.create(result)
                .assertNext(resp -> {
                    assertEquals(HttpStatus.NOT_FOUND, resp.getStatusCode());
                    GlobalErrorMessage er = resp.getBody();
                    assertNotNull(er);
                    assertEquals("Not Found", er.type());
                    // note: code uses FORBIDDEN.value() as the body.status
                    assertEquals(404, er.status());
                    assertEquals(NoSuchEntityException.class.toString(), er.title());
                    assertEquals(msg, er.detail());
                    assertNotNull(er.instance());
                    assertTrue(Pattern.matches(
                            "[0-9a-fA-F\\-]{36}", er.instance()
                    ));
                })
                .verifyComplete();
    }

    @Test
    void handleMissingRequiredDataException_returnsBadRequestWithCorrectApiErrorResponse() {
        RequestPath mockPath = mock(RequestPath.class);
        when(mockPath.toString()).thenReturn("/missing-data");
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getPath()).thenReturn(mockPath);

        String errorMessage = "Required data is missing";
        MissingRequiredDataException exception = new MissingRequiredDataException(errorMessage);

        Mono<ResponseEntity<GlobalErrorMessage>> result =
                globalExceptionHandler.handleMissingRequiredDataException(exception, request);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
                    GlobalErrorMessage responseBody = responseEntity.getBody();
                    assertNotNull(responseBody);
                    assertEquals("Bad Request", responseBody.type());
                    assertEquals(MissingRequiredDataException.class.toString(), responseBody.title());
                    assertEquals(400, responseBody.status());
                    assertEquals(errorMessage, responseBody.detail());
                    assertNotNull(responseBody.instance());
                    assertTrue(Pattern.matches("[0-9a-fA-F\\-]{36}", responseBody.instance()));
                })
                .verifyComplete();
    }

    @Test
    void handleInvalidSignatureConfigurationException_returnsBadRequestWithCorrectApiErrorResponse() {
        RequestPath mockPath = mock(RequestPath.class);
        when(mockPath.toString()).thenReturn("/invalid-signature");
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getPath()).thenReturn(mockPath);

        String errorMessage = "Invalid signature configuration";
        InvalidSignatureConfigurationException exception = new InvalidSignatureConfigurationException(errorMessage);

        Mono<ResponseEntity<GlobalErrorMessage>> result =
                globalExceptionHandler.handleInvalidSignatureConfigurationException(exception, request);

        StepVerifier.create(result)
                .assertNext(responseEntity -> {
                    assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
                    GlobalErrorMessage responseBody = responseEntity.getBody();
                    assertNotNull(responseBody);
                    assertEquals("Bad Request", responseBody.type());
                    assertEquals(InvalidSignatureConfigurationException.class.toString(), responseBody.title());
                    assertEquals(400, responseBody.status());
                    assertEquals(errorMessage, responseBody.detail());
                    assertNotNull(responseBody.instance());
                    assertTrue(Pattern.matches("[0-9a-fA-F\\-]{36}", responseBody.instance()));
                })
                .verifyComplete();
    }
}