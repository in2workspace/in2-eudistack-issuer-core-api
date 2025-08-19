package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.exception.*;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.text.ParseException;
import java.lang.reflect.Method;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;
    private ServerHttpRequest mockRequest;
    private RequestPath mockPath;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
        mockRequest = mock(ServerHttpRequest.class);
        mockPath = mock(RequestPath.class);
        when(mockRequest.getPath()).thenReturn(mockPath);
    }

    // ---------- helpers per invocar mètodes privats amb reflexió ----------

    private String invokeResolveDetail(Exception ex, String fallback) throws Exception {
        Method m = GlobalExceptionHandler.class.getDeclaredMethod("resolveDetail", Exception.class, String.class);
        m.setAccessible(true);
        return (String) m.invoke(handler, ex, fallback);
    }

    private GlobalErrorMessage invokeBuildError(
            String type, String title, HttpStatus status, String detail, Exception ex
    ) throws Exception {
        Method m = GlobalExceptionHandler.class.getDeclaredMethod(
                "buildError",
                String.class, String.class, HttpStatus.class, String.class, Exception.class, ServerHttpRequest.class
        );
        m.setAccessible(true);
        return (GlobalErrorMessage) m.invoke(handler, type, title, status, detail, ex, mockRequest);
    }

    @SuppressWarnings("unchecked")
    private Mono<GlobalErrorMessage> invokeHandleWith(
            Exception ex, String type, String title, HttpStatus status, String fallbackDetail
    ) throws Exception {
        Method m = GlobalExceptionHandler.class.getDeclaredMethod(
                "handleWith",
                Exception.class, ServerHttpRequest.class, String.class, String.class, HttpStatus.class, String.class
        );
        m.setAccessible(true);
        return (Mono<GlobalErrorMessage>) m.invoke(handler, ex, mockRequest, type, title, status, fallbackDetail);
    }

    // ------------------- TESTS resolveDetail -------------------

    @Test
    void resolveDetail_returnsFallback_whenMessageIsNull() throws Exception {
        String out = invokeResolveDetail(new Exception((String) null), "fallback");
        assertEquals("fallback", out);
    }

    @Test
    void resolveDetail_returnsFallback_whenMessageIsBlank() throws Exception {
        String out = invokeResolveDetail(new Exception("   "), "fallback");
        assertEquals("fallback", out);
    }

    @Test
    void resolveDetail_returnsMessage_whenPresent() throws Exception {
        String out = invokeResolveDetail(new Exception("boom"), "fallback");
        assertEquals("boom", out);
    }

    // ------------------- TESTS buildError -------------------

    @Test
    void buildError_constructsGlobalErrorMessage_withExpectedFields_andUuidInstance() throws Exception {
        String type = "TEST_TYPE";
        String title = "Test Title";
        HttpStatus status = HttpStatus.BAD_REQUEST;
        String detail = "Some detail";
        Exception ex = new IllegalArgumentException("bad arg");

        GlobalErrorMessage gem = invokeBuildError(type, title, status, detail, ex);

        assertNotNull(gem);
        assertEquals(type, gem.type());
        assertEquals(title, gem.title());
        assertEquals(status.value(), gem.status());
        assertEquals(detail, gem.detail());
        assertDoesNotThrow(() -> UUID.fromString(gem.instance()));
    }

    // ------------------- TESTS handleWith -------------------

    @Test
    void handleWith_usesExceptionMessage_whenPresent() throws Exception {
        Exception ex = new Exception("explicit message");
        Mono<GlobalErrorMessage> mono = invokeHandleWith(
                ex, "TYPE_A", "Title A", HttpStatus.NOT_FOUND, "fallback detail"
        );

        StepVerifier.create(mono)
                .assertNext(gem -> {
                    assertEquals("TYPE_A", gem.type());
                    assertEquals("Title A", gem.title());
                    assertEquals(HttpStatus.NOT_FOUND.value(), gem.status());
                    assertEquals("explicit message", gem.detail());
                    assertDoesNotThrow(() -> UUID.fromString(gem.instance()));
                })
                .verifyComplete();
    }

    @Test
    void handleWith_usesFallback_whenMessageIsNullOrBlank() throws Exception {
        Exception exNull = new Exception((String) null);
        Exception exBlank = new Exception("  ");

        Mono<GlobalErrorMessage> monoNull = invokeHandleWith(
                exNull, "TYPE_B", "Title B", HttpStatus.INTERNAL_SERVER_ERROR, "fb"
        );
        Mono<GlobalErrorMessage> monoBlank = invokeHandleWith(
                exBlank, "TYPE_B", "Title B", HttpStatus.INTERNAL_SERVER_ERROR, "fb"
        );

        StepVerifier.create(monoNull)
                .assertNext(gem -> {
                    assertEquals("TYPE_B", gem.type());
                    assertEquals("Title B", gem.title());
                    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), gem.status());
                    assertEquals("fb", gem.detail());
                    assertDoesNotThrow(() -> UUID.fromString(gem.instance()));
                })
                .verifyComplete();

        StepVerifier.create(monoBlank)
                .assertNext(gem -> {
                    assertEquals("TYPE_B", gem.type());
                    assertEquals("Title B", gem.title());
                    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), gem.status());
                    assertEquals("fb", gem.detail());
                    assertDoesNotThrow(() -> UUID.fromString(gem.instance()));
                })
                .verifyComplete();
    }

    private void assertGem(
            GlobalErrorMessage gem,
            String expectedType,
            String expectedTitle,
            HttpStatus expectedStatus,
            String expectedDetail
    ) {
        assertNotNull(gem);
        assertEquals(expectedType, gem.type());
        assertEquals(expectedTitle, gem.title());
        assertEquals(expectedStatus.value(), gem.status());
        assertEquals(expectedDetail, gem.detail());
        // instance ha de ser un UUID
        assertDoesNotThrow(() -> java.util.UUID.fromString(gem.instance()));
    }

// -------------------- TESTS: handleCredentialTypeUnsupported --------------------

    @Test
    void handleCredentialTypeUnsupported_usesFallback_whenMessageNullOrBlank() {
        // message null
        CredentialTypeUnsupportedException exNull = new CredentialTypeUnsupportedException(null);
        Mono<GlobalErrorMessage> m1 = handler.handleCredentialTypeUnsupported(exNull, mockRequest);

        StepVerifier.create(m1)
                .assertNext(gem -> assertGem(
                        gem,
                        // type
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.UNSUPPORTED_CREDENTIAL_TYPE,
                        // title
                        "Unsupported credential type",
                        // status
                        HttpStatus.NOT_FOUND,
                        // fallback detail
                        "The given credential type is not supported"
                ))
                .verifyComplete();

        // message blank
        CredentialTypeUnsupportedException exBlank = new CredentialTypeUnsupportedException("   ");
        Mono<GlobalErrorMessage> m2 = handler.handleCredentialTypeUnsupported(exBlank, mockRequest);

        StepVerifier.create(m2)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.UNSUPPORTED_CREDENTIAL_TYPE,
                        "Unsupported credential type",
                        HttpStatus.NOT_FOUND,
                        "The given credential type is not supported"
                ))
                .verifyComplete();
    }

    @Test
    void handleCredentialTypeUnsupported_usesExceptionMessage_whenPresent() {
        CredentialTypeUnsupportedException ex = new CredentialTypeUnsupportedException("custom msg");
        Mono<GlobalErrorMessage> mono = handler.handleCredentialTypeUnsupported(ex, mockRequest);

        StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.UNSUPPORTED_CREDENTIAL_TYPE,
                        "Unsupported credential type",
                        HttpStatus.NOT_FOUND,
                        "custom msg"
                ))
                .verifyComplete();
    }

// -------------------- TESTS: handleNoSuchElementException --------------------

    @Test
    void handleNoSuchElementException_usesFallback_whenMessageNullOrBlank() {
        NoSuchElementException exNull = new NoSuchElementException("The requested resource was not found");
        Mono<GlobalErrorMessage> m1 = handler.handleNoSuchElementException(exNull, mockRequest);

        StepVerifier.create(m1)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.NO_SUCH_ELEMENT,
                        "Resource not found",
                        HttpStatus.NOT_FOUND,
                        "The requested resource was not found"
                ))
                .verifyComplete();

        NoSuchElementException exBlank = new NoSuchElementException("  ");
        Mono<GlobalErrorMessage> m2 = handler.handleNoSuchElementException(exBlank, mockRequest);

        StepVerifier.create(m2)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.NO_SUCH_ELEMENT,
                        "Resource not found",
                        HttpStatus.NOT_FOUND,
                        "The requested resource was not found"
                ))
                .verifyComplete();
    }

    @Test
    void handleNoSuchElementException_usesExceptionMessage_whenPresent() {
        NoSuchElementException ex = new NoSuchElementException("not here");
        Mono<GlobalErrorMessage> mono = handler.handleNoSuchElementException(ex, mockRequest);

        StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.NO_SUCH_ELEMENT,
                        "Resource not found",
                        HttpStatus.NOT_FOUND,
                        "not here"
                ))
                .verifyComplete();
    }

// -------------------- TESTS: handleExpiredCache --------------------

    @Test
    void handleExpiredCache_usesFallback_whenMessageNullOrBlank() {
        ExpiredCacheException exNull = new ExpiredCacheException(null);
        Mono<GlobalErrorMessage> m1 = handler.handleExpiredCache(exNull, mockRequest);

        StepVerifier.create(m1)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.VC_DOES_NOT_EXIST,
                        "Credential does not exist",
                        HttpStatus.BAD_REQUEST,
                        "The given credential ID does not match with any credentials"
                ))
                .verifyComplete();

        ExpiredCacheException exBlank = new ExpiredCacheException("   ");
        Mono<GlobalErrorMessage> m2 = handler.handleExpiredCache(exBlank, mockRequest);

        StepVerifier.create(m2)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.VC_DOES_NOT_EXIST,
                        "Credential does not exist",
                        HttpStatus.BAD_REQUEST,
                        "The given credential ID does not match with any credentials"
                ))
                .verifyComplete();
    }

    @Test
    void handleExpiredCache_usesExceptionMessage_whenPresent() {
        ExpiredCacheException ex = new ExpiredCacheException("cache expired");
        Mono<GlobalErrorMessage> mono = handler.handleExpiredCache(ex, mockRequest);

        StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.VC_DOES_NOT_EXIST,
                        "Credential does not exist",
                        HttpStatus.BAD_REQUEST,
                        "cache expired"
                ))
                .verifyComplete();
    }

    @Test
    void handleExpiredPreAuthorizedCode_usesExceptionMessage_whenPresent() {
        ExpiredPreAuthorizedCodeException ex = new ExpiredPreAuthorizedCodeException("expired!");
        Mono<GlobalErrorMessage> mono = handler.handleExpiredPreAuthorizedCode(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.EXPIRED_PRE_AUTHORIZED_CODE,
                        "Expired pre-authorized code",
                        HttpStatus.NOT_FOUND,
                        "expired!"
                ))
                .verifyComplete();
    }

    @Test
    void handleExpiredPreAuthorizedCode_usesFallback_whenMessageNullOrBlank() {
        ExpiredPreAuthorizedCodeException exNull = new ExpiredPreAuthorizedCodeException((String) null);
        ExpiredPreAuthorizedCodeException exBlank = new ExpiredPreAuthorizedCodeException("   ");

        Mono<GlobalErrorMessage> mNull = handler.handleExpiredPreAuthorizedCode(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleExpiredPreAuthorizedCode(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.EXPIRED_PRE_AUTHORIZED_CODE,
                        "Expired pre-authorized code",
                        HttpStatus.NOT_FOUND,
                        "The pre-authorized code has expired, has been used, or does not exist."
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.EXPIRED_PRE_AUTHORIZED_CODE,
                        "Expired pre-authorized code",
                        HttpStatus.NOT_FOUND,
                        "The pre-authorized code has expired, has been used, or does not exist."
                ))
                .verifyComplete();
    }

// ===================== handleInvalidOrMissingProof =====================

    @Test
    void handleInvalidOrMissingProof_usesExceptionMessage_whenPresent() {
        InvalidOrMissingProofException ex = new InvalidOrMissingProofException("bad proof");
        Mono<GlobalErrorMessage> mono = handler.handleInvalidOrMissingProof(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.INVALID_OR_MISSING_PROOF,
                        "Invalid or missing proof",
                        HttpStatus.NOT_FOUND,
                        "bad proof"
                ))
                .verifyComplete();
    }

    @Test
    void handleInvalidOrMissingProof_usesFallback_whenMessageNullOrBlank() {
        InvalidOrMissingProofException exNull = new InvalidOrMissingProofException((String) null);
        InvalidOrMissingProofException exBlank = new InvalidOrMissingProofException(" ");

        Mono<GlobalErrorMessage> mNull = handler.handleInvalidOrMissingProof(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleInvalidOrMissingProof(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.INVALID_OR_MISSING_PROOF,
                        "Invalid or missing proof",
                        HttpStatus.NOT_FOUND,
                        "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce."
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.INVALID_OR_MISSING_PROOF,
                        "Invalid or missing proof",
                        HttpStatus.NOT_FOUND,
                        "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce."
                ))
                .verifyComplete();
    }

// ===================== handleInvalidToken =====================

    @Test
    void handleInvalidToken_usesExceptionMessage_whenPresent() {
        InvalidTokenException ex = new InvalidTokenException("Message");
        Mono<GlobalErrorMessage> mono = handler.handleInvalidToken(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.INVALID_TOKEN,
                        "Invalid token",
                        HttpStatus.NOT_FOUND,
                        "Message"
                ))
                .verifyComplete();
    }

    @Test
    void handleInvalidToken_usesFallback_whenMessageNullOrBlank() {
        InvalidTokenException exNull = new InvalidTokenException((String) null);
        InvalidTokenException exBlank = new InvalidTokenException("   ");

        Mono<GlobalErrorMessage> mNull = handler.handleInvalidToken(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleInvalidToken(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.INVALID_TOKEN,
                        "Invalid token",
                        HttpStatus.NOT_FOUND,
                        "The request contains the wrong Access Token or the Access Token is missing"
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.INVALID_TOKEN,
                        "Invalid token",
                        HttpStatus.NOT_FOUND,
                        "The request contains the wrong Access Token or the Access Token is missing"
                ))
                .verifyComplete();
    }

// ===================== handleUserDoesNotExist =====================

    @Test
    void handleUserDoesNotExist_usesExceptionMessage_whenPresent() {
        UserDoesNotExistException ex = new UserDoesNotExistException("no user");
        Mono<GlobalErrorMessage> mono = handler.handleUserDoesNotExist(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.USER_DOES_NOT_EXIST,
                        "User does not exist",
                        HttpStatus.NOT_FOUND,
                        "no user"
                ))
                .verifyComplete();
    }

    @Test
    void handleUserDoesNotExist_usesFallback_whenMessageNullOrBlank() {
        UserDoesNotExistException exNull = new UserDoesNotExistException((String) null);
        UserDoesNotExistException exBlank = new UserDoesNotExistException(" ");

        Mono<GlobalErrorMessage> mNull = handler.handleUserDoesNotExist(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleUserDoesNotExist(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.USER_DOES_NOT_EXIST,
                        "User does not exist",
                        HttpStatus.NOT_FOUND,
                        "User does not exist"
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.USER_DOES_NOT_EXIST,
                        "User does not exist",
                        HttpStatus.NOT_FOUND,
                        "User does not exist"
                ))
                .verifyComplete();
    }

// ===================== handleVcTemplateDoesNotExist =====================

    @Test
    void handleVcTemplateDoesNotExist_usesExceptionMessage_whenPresent() {
        VcTemplateDoesNotExistException ex = new VcTemplateDoesNotExistException("no template");
        Mono<GlobalErrorMessage> mono = handler.handleVcTemplateDoesNotExist(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST,
                        "VC template does not exist",
                        HttpStatus.NOT_FOUND,
                        "no template"
                ))
                .verifyComplete();
    }

    @Test
    void handleVcTemplateDoesNotExist_usesFallback_whenMessageNullOrBlank() {
        VcTemplateDoesNotExistException exNull = new VcTemplateDoesNotExistException((String) null);
        VcTemplateDoesNotExistException exBlank = new VcTemplateDoesNotExistException("   ");

        Mono<GlobalErrorMessage> mNull = handler.handleVcTemplateDoesNotExist(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleVcTemplateDoesNotExist(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST,
                        "VC template does not exist",
                        HttpStatus.NOT_FOUND,
                        "The given template name is not supported"
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        es.in2.issuer.backend.backoffice.domain.util.CredentialResponseErrorCodes.VC_TEMPLATE_DOES_NOT_EXIST,
                        "VC template does not exist",
                        HttpStatus.NOT_FOUND,
                        "The given template name is not supported"
                ))
                .verifyComplete();
    }

    // ===================== handleParseException =====================

    @Test
    void handleParseException_usesExceptionMessage_whenPresent() {
        ParseException ex = new ParseException("bad date", 0);
        Mono<GlobalErrorMessage> mono = handler.handleParseException(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        "parse_error",
                        "Parse error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "bad date"
                ))
                .verifyComplete();
    }

    @Test
    void handleParseException_usesFallback_whenMessageNullOrBlank() {
        ParseException exNull = new ParseException(null, 0);
        ParseException exBlank = new ParseException("   ", 0);

        Mono<GlobalErrorMessage> mNull = handler.handleParseException(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleParseException(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        "parse_error",
                        "Parse error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal parsing error occurred."
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        "parse_error",
                        "Parse error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal parsing error occurred."
                ))
                .verifyComplete();
    }

// ===================== handleBase45Exception =====================

    @Test
    void handleBase45Exception_usesExceptionMessage_whenPresent() {
        Base45Exception ex = new Base45Exception("decode failed");
        Mono<GlobalErrorMessage> mono = handler.handleBase45Exception(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        "base45_decode_error",
                        "Base45 decoding error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "decode failed"
                ))
                .verifyComplete();
    }

    @Test
    void handleBase45Exception_usesFallback_whenMessageNullOrBlank() {
        Base45Exception exNull = new Base45Exception((String) null);
        Base45Exception exBlank = new Base45Exception("   ");

        Mono<GlobalErrorMessage> mNull = handler.handleBase45Exception(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleBase45Exception(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        "base45_decode_error",
                        "Base45 decoding error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal Base45 decoding error occurred."
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        "base45_decode_error",
                        "Base45 decoding error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal Base45 decoding error occurred."
                ))
                .verifyComplete();
    }

// ===================== handleCreateDateException =====================

    @Test
    void handleCreateDateException_usesExceptionMessage_whenPresent() {
        CreateDateException ex = new CreateDateException("cannot build date");
        Mono<GlobalErrorMessage> mono = handler.handleCreateDateException(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        "create_date_error",
                        "Create date error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "cannot build date"
                ))
                .verifyComplete();
    }

    @Test
    void handleCreateDateException_usesFallback_whenMessageNullOrBlank() {
        CreateDateException exNull = new CreateDateException((String) null);
        CreateDateException exBlank = new CreateDateException("");

        Mono<GlobalErrorMessage> mNull = handler.handleCreateDateException(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleCreateDateException(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        "create_date_error",
                        "Create date error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal date creation error occurred."
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        "create_date_error",
                        "Create date error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal date creation error occurred."
                ))
                .verifyComplete();
    }

// ===================== handleSignedDataParsingException =====================

    @Test
    void handleSignedDataParsingException_usesExceptionMessage_whenPresent() {
        SignedDataParsingException ex = new SignedDataParsingException("bad signature payload");
        Mono<GlobalErrorMessage> mono = handler.handleSignedDataParsingException(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        "signed_data_parse_error",
                        "Signed data parsing error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "bad signature payload"
                ))
                .verifyComplete();
    }

    @Test
    void handleSignedDataParsingException_usesFallback_whenMessageNullOrBlank() {
        SignedDataParsingException exNull = new SignedDataParsingException((String) null);
        SignedDataParsingException exBlank = new SignedDataParsingException("   ");

        Mono<GlobalErrorMessage> mNull = handler.handleSignedDataParsingException(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleSignedDataParsingException(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        "signed_data_parse_error",
                        "Signed data parsing error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal signed data parsing error occurred."
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        "signed_data_parse_error",
                        "Signed data parsing error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal signed data parsing error occurred."
                ))
                .verifyComplete();
    }

// ===================== handleAuthenticSourcesUserParsingException =====================

    @Test
    void handleAuthenticSourcesUserParsingException_usesExceptionMessage_whenPresent() {
        AuthenticSourcesUserParsingException ex = new AuthenticSourcesUserParsingException("auth sources parse failed");
        Mono<GlobalErrorMessage> mono = handler.handleAuthenticSourcesUserParsingException(ex, mockRequest);

        reactor.test.StepVerifier.create(mono)
                .assertNext(gem -> assertGem(
                        gem,
                        "authentic_sources_user_parsing_error",
                        "Authentic sources user parsing error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "auth sources parse failed"
                ))
                .verifyComplete();
    }

    @Test
    void handleAuthenticSourcesUserParsingException_usesFallback_whenMessageNullOrBlank() {
        AuthenticSourcesUserParsingException exNull = new AuthenticSourcesUserParsingException((String) null);
        AuthenticSourcesUserParsingException exBlank = new AuthenticSourcesUserParsingException("");

        Mono<GlobalErrorMessage> mNull = handler.handleAuthenticSourcesUserParsingException(exNull, mockRequest);
        Mono<GlobalErrorMessage> mBlank = handler.handleAuthenticSourcesUserParsingException(exBlank, mockRequest);

        reactor.test.StepVerifier.create(mNull)
                .assertNext(gem -> assertGem(
                        gem,
                        "authentic_sources_user_parsing_error",
                        "Authentic sources user parsing error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal authentic-sources user parsing error occurred."
                ))
                .verifyComplete();

        reactor.test.StepVerifier.create(mBlank)
                .assertNext(gem -> assertGem(
                        gem,
                        "authentic_sources_user_parsing_error",
                        "Authentic sources user parsing error",
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "An internal authentic-sources user parsing error occurred."
                ))
                .verifyComplete();
    }

}
