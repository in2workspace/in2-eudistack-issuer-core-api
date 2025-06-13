package es.in2.issuer.backend.backoffice.infrastructure.controller;


import es.in2.issuer.backend.backoffice.domain.exception.*;
import es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.web.context.request.WebRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.NoSuchElementException;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {
    private static GlobalExceptionHandler globalExceptionHandler;

    @BeforeEach
    void setUp() {
        globalExceptionHandler = new GlobalExceptionHandler();
        WebRequest mockWebRequest = mock(WebRequest.class);
        when(mockWebRequest.getDescription(false)).thenReturn("WebRequestDescription");
    }

    private static Stream<Arguments> provideHandlersWithDescription() {
        return Stream.of(
                Arguments.of(
                        new CredentialTypeUnsupportedException("Test Message"),
                        CredentialResponseErrorCodes.UNSUPPORTED_CREDENTIAL_TYPE,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleCredentialTypeUnsupported(ex)
                ),
                Arguments.of(
                        new NoSuchElementException("Test Message"),
                        CredentialResponseErrorCodes.NOT_FOUND_RESOURCE,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleNoSuchElementException((NoSuchElementException) ex)
                ),
                Arguments.of(
                        new ExpiredCacheException("Test Message"),
                        CredentialResponseErrorCodes.VC_DOES_NOT_EXIST,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleExpiredCacheException(ex)
                ),
                Arguments.of(
                        new ExpiredPreAuthorizedCodeException("Test Message"),
                        CredentialResponseErrorCodes.EXPIRED_PRE_AUTHORIZED_CODE,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.expiredPreAuthorizedCode(ex)
                ),
                Arguments.of(
                        new InvalidOrMissingProofException("Test Message"),
                        CredentialResponseErrorCodes.INVALID_OR_MISSING_PROOF,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleInvalidOrMissingProof(ex)
                ),
                Arguments.of(
                        new UserDoesNotExistException("Test Message"),
                        CredentialResponseErrorCodes.USER_DOES_NOT_EXIST,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleUserDoesNotExistException(ex)
                ),
                Arguments.of(
                        new VcTemplateDoesNotExistException("Test Message"),
                        CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.vcTemplateDoesNotExist(ex)
                ),
                Arguments.of(
                        new Base45Exception("Test Message"),
                        CredentialResponseErrorCodes.BASE_45_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleBase45Exception((Base45Exception) ex)
                ),
                Arguments.of(
                        new CreateDateException("Test Message"),
                        CredentialResponseErrorCodes.CREATE_DATE_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleCreateDateException((CreateDateException) ex)
                ),
                Arguments.of(
                        new SignedDataParsingException("Test Message"),
                        CredentialResponseErrorCodes.SIGNED_DATA_PARSING_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleSignedDataParsingException((SignedDataParsingException) ex)
                ),
                Arguments.of(
                        new AuthenticSourcesUserParsingException("Test Message"),
                        CredentialResponseErrorCodes.AUTHENTIC_SOURCES_USER_PARSING_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleSignedDataParsingException((AuthenticSourcesUserParsingException) ex)
                ),
                Arguments.of(
                        new ParseCredentialJsonException("Test Message"),
                        CredentialResponseErrorCodes.PARSE_CREDENTIAL_JSON_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleParseCredentialJsonException((ParseCredentialJsonException) ex)
                ),
                Arguments.of(
                        new TemplateReadException("Test Message"),
                        CredentialResponseErrorCodes.TEMPLATE_READ_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleTemplateReadException((TemplateReadException) ex)
                ),
                Arguments.of(
                        new ProofValidationException("Test Message"),
                        CredentialResponseErrorCodes.PROOF_VALIDATION_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleProofValidationException((ProofValidationException) ex)
                ),
                Arguments.of(
                        new NoCredentialFoundException("Test Message"),
                        CredentialResponseErrorCodes.CREDENTIAL_NOT_FOUND,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleNoCredentialFoundException((NoCredentialFoundException) ex)
                ),
                Arguments.of(
                        new PreAuthorizationCodeGetException("Test Message"),
                        CredentialResponseErrorCodes.PRE_AUTHORIZATION_CODE_GET_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handlePreAuthorizationCodeGetException((PreAuthorizationCodeGetException) ex)
                ),
                Arguments.of(
                        new CredentialOfferNotFoundException("Test Message"),
                        CredentialResponseErrorCodes.CREDENTIAL_OFFER_NOT_FOUND,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleCustomCredentialOfferNotFoundException((CredentialOfferNotFoundException) ex)
                ),
                Arguments.of(
                        new CredentialAlreadyIssuedException("Test Message"),
                        CredentialResponseErrorCodes.CREDENTIAL_ALREADY_ISSUED,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleCredentialAlreadyIssuedException((CredentialAlreadyIssuedException) ex)
                ),
                Arguments.of(
                        new OperationNotSupportedException("Test Message"),
                        CredentialResponseErrorCodes.OPERATION_NOT_SUPPORTED,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleOperationNotSupportedException(ex)
                ),
                Arguments.of(
                        new JWTVerificationException("Test Message"),
                        CredentialResponseErrorCodes.JWT_VERIFICATION_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleJWTVerificationException((JWTVerificationException) ex)
                ),
                Arguments.of(
                        new ResponseUriException("Test Message"),
                        CredentialResponseErrorCodes.RESPONSE_URI_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleResponseUriException(ex)
                ),
                Arguments.of(
                        new InsufficientPermissionException("Test Message"),
                        CredentialResponseErrorCodes.INSUFFICIENT_PERMISSION,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleInsufficientPermissionException(ex)
                ),
                Arguments.of(
                        new EmailCommunicationException("Test Message"),
                        CredentialResponseErrorCodes.EMAIL_COMMUNICATION_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleEmailCommunicationException((EmailCommunicationException) ex)
                )

        );
    }

    private static Stream<Arguments> provideHandlersWithoutDescription() {
        return Stream.of(
                Arguments.of(
                        new CredentialTypeUnsupportedException(""),
                        CredentialResponseErrorCodes.UNSUPPORTED_CREDENTIAL_TYPE,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleCredentialTypeUnsupported(ex)
                ),
                Arguments.of(
                        new NoSuchElementException(""),
                        CredentialResponseErrorCodes.NOT_FOUND_RESOURCE,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleNoSuchElementException((NoSuchElementException) ex)
                ),
                Arguments.of(
                        new ExpiredCacheException(""),
                        CredentialResponseErrorCodes.VC_DOES_NOT_EXIST,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleExpiredCacheException(ex)
                ),
                Arguments.of(
                        new ExpiredPreAuthorizedCodeException(""),
                        CredentialResponseErrorCodes.EXPIRED_PRE_AUTHORIZED_CODE,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.expiredPreAuthorizedCode(ex)
                ),
                Arguments.of(
                        new InvalidOrMissingProofException(""),
                        CredentialResponseErrorCodes.INVALID_OR_MISSING_PROOF,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleInvalidOrMissingProof(ex)
                ),
                Arguments.of(
                        new UserDoesNotExistException(""),
                        CredentialResponseErrorCodes.USER_DOES_NOT_EXIST,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleUserDoesNotExistException(ex)
                ),
                Arguments.of(
                        new VcTemplateDoesNotExistException(""),
                        CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.vcTemplateDoesNotExist(ex)
                ),
                Arguments.of(
                        new ParseException("", 0),
                        CredentialResponseErrorCodes.PARSING_CREDENTIAL_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleParseException((ParseException) ex)
                ),
                Arguments.of(
                        new Base45Exception(""),
                        CredentialResponseErrorCodes.BASE_45_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleBase45Exception((Base45Exception) ex)
                ),
                Arguments.of(
                        new CreateDateException(""),
                        CredentialResponseErrorCodes.CREATE_DATE_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleCreateDateException((CreateDateException) ex)
                ),
                Arguments.of(
                        new SignedDataParsingException(""),
                        CredentialResponseErrorCodes.SIGNED_DATA_PARSING_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleSignedDataParsingException((SignedDataParsingException) ex)
                ),
                Arguments.of(
                        new AuthenticSourcesUserParsingException(""),
                        CredentialResponseErrorCodes.AUTHENTIC_SOURCES_USER_PARSING_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleSignedDataParsingException((AuthenticSourcesUserParsingException) ex)
                ),
                Arguments.of(
                        new ParseCredentialJsonException(""),
                        CredentialResponseErrorCodes.PARSE_CREDENTIAL_JSON_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleParseCredentialJsonException((ParseCredentialJsonException) ex)
                ),
                Arguments.of(
                        new TemplateReadException(""),
                        CredentialResponseErrorCodes.TEMPLATE_READ_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleTemplateReadException((TemplateReadException) ex)
                ),
                Arguments.of(
                        new ProofValidationException(""),
                        CredentialResponseErrorCodes.PROOF_VALIDATION_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleProofValidationException((ProofValidationException) ex)
                ),
                Arguments.of(
                        new NoCredentialFoundException(""),
                        CredentialResponseErrorCodes.CREDENTIAL_NOT_FOUND,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleNoCredentialFoundException((NoCredentialFoundException) ex)
                ),
                Arguments.of(
                        new PreAuthorizationCodeGetException(""),
                        CredentialResponseErrorCodes.PRE_AUTHORIZATION_CODE_GET_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handlePreAuthorizationCodeGetException((PreAuthorizationCodeGetException) ex)
                ),
                Arguments.of(
                        new CredentialOfferNotFoundException(""),
                        CredentialResponseErrorCodes.CREDENTIAL_OFFER_NOT_FOUND,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleCustomCredentialOfferNotFoundException((CredentialOfferNotFoundException) ex)
                ),
                Arguments.of(
                        new CredentialAlreadyIssuedException(""),
                        CredentialResponseErrorCodes.CREDENTIAL_ALREADY_ISSUED,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleCredentialAlreadyIssuedException((CredentialAlreadyIssuedException) ex)
                ),
                Arguments.of(
                        new OperationNotSupportedException(""),
                        CredentialResponseErrorCodes.OPERATION_NOT_SUPPORTED,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleOperationNotSupportedException(ex)
                ),
                Arguments.of(
                        new JWTVerificationException(""),
                        CredentialResponseErrorCodes.JWT_VERIFICATION_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleJWTVerificationException((JWTVerificationException) ex)
                ),
                Arguments.of(
                        new ResponseUriException(""),
                        CredentialResponseErrorCodes.RESPONSE_URI_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleResponseUriException(ex)
                ),
                Arguments.of(
                        new InsufficientPermissionException(""),
                        CredentialResponseErrorCodes.INSUFFICIENT_PERMISSION,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleInsufficientPermissionException(ex)
                ),
                Arguments.of(
                        new EmailCommunicationException(""),
                        CredentialResponseErrorCodes.EMAIL_COMMUNICATION_ERROR,
                        (Function<Exception, Mono<CredentialErrorResponse>>) ex -> globalExceptionHandler.handleEmailCommunicationException((EmailCommunicationException) ex)
                )

        );
    }

    @ParameterizedTest
    @MethodSource("provideHandlersWithDescription")
    void handle_withCustomMessage_throwExceptionWithCustomMessage(
            Exception exception,
            String errorCode,
            Function<Exception, Mono<CredentialErrorResponse>> handlerFunction) {
        var expected = new CredentialErrorResponse(errorCode, exception.getMessage());

        var result = handlerFunction.apply(exception);

        StepVerifier.create(result)
                .assertNext(response ->
                        assertThat(response).isEqualTo(expected))
                .verifyComplete();
    }

    @ParameterizedTest
    @MethodSource("provideHandlersWithoutDescription")
    void handle_withoutCustomMessage_throwExceptionWithDefaultMessage(
            Exception exception,
            String errorCode,
            Function<Exception, Mono<CredentialErrorResponse>> handlerFunction) {
        var expected = new CredentialErrorResponse(errorCode, exception.getMessage());

        var result = handlerFunction.apply(exception);

        StepVerifier.create(result)
                .assertNext(response ->
                        assertThat(response).isNotEqualTo(expected))
                .verifyComplete();
    }
}