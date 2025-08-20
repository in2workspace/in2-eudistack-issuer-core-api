package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.exception.*;
import es.in2.issuer.backend.backoffice.domain.util.BackofficeErrorTypes;
import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

//todo make recursive
class BackofficeExceptionHandlerTest {

    private ErrorResponseFactory errors;          // mock
    private BackofficeExceptionHandler handler;   // SUT
    private ServerHttpRequest request;

    @BeforeEach
    void setUp() {
        errors = mock(ErrorResponseFactory.class);
        handler = new BackofficeExceptionHandler(errors);
        request = MockServerHttpRequest.get("/any").build();
    }

    private void assertGem(GlobalErrorMessage gem,
                           String expectedType,
                           String expectedTitle,
                           HttpStatus expectedStatus,
                           String expectedDetail) {
        assertNotNull(gem);
        assertEquals(expectedType, gem.type());
        assertEquals(expectedTitle, gem.title());
        assertEquals(expectedStatus.value(), gem.status());
        assertEquals(expectedDetail, gem.detail());
        assertDoesNotThrow(() -> UUID.fromString(gem.instance())); // instance ha de ser UUID
    }

    // ------------------- AuthenticSourcesUserParsingException -------------------

    @Test
    void handleAuthenticSourcesUserParsingException_usesExceptionMessage_whenPresent() {
        var ex = new AuthenticSourcesUserParsingException("auth sources parse failed");

        // EXPECTED constants del handler
        String type   = GlobalErrorTypes.PARSE_ERROR.getCode();
        String title  = "Authentic sources user parsing error";
        HttpStatus st = HttpStatus.INTERNAL_SERVER_ERROR;
        String fallback = "An internal authentic-sources user parsing error occurred.";

        // Preparem el Mono que retornarà el mock del factory
        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        Mono<GlobalErrorMessage> mono = handler.handleAuthenticSourcesUserParsingException(ex, request);

        StepVerifier.create(mono)
                .assertNext(gem -> assertGem(gem, type, title, st, "auth sources parse failed"))
                .verifyComplete();

        // verifiquem la delegació amb els paràmetres exactes
        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleAuthenticSourcesUserParsingException_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new AuthenticSourcesUserParsingException((String) null);
        var exBlank = new AuthenticSourcesUserParsingException("");

        String type   = GlobalErrorTypes.PARSE_ERROR.getCode();
        String title  = "Authentic sources user parsing error";
        HttpStatus st = HttpStatus.INTERNAL_SERVER_ERROR;
        String fallback = "An internal authentic-sources user parsing error occurred.";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleAuthenticSourcesUserParsingException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleAuthenticSourcesUserParsingException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // ------------------- TemplateReadException -------------------

    @Test
    void handleTemplateReadException_usesExceptionMessage_whenPresent() {
        var ex = new TemplateReadException("cannot read template");

        String type   = BackofficeErrorTypes.TEMPLATE_READ_ERROR.getCode();
        String title  = "Template read error";
        HttpStatus st = HttpStatus.INTERNAL_SERVER_ERROR;
        String fallback = "An internal template read error occurred.";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleTemplateReadException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "cannot read template"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleTemplateReadException_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new TemplateReadException((String) null);
        var exBlank = new TemplateReadException("");

        String type   = BackofficeErrorTypes.TEMPLATE_READ_ERROR.getCode();
        String title  = "Template read error";
        HttpStatus st = HttpStatus.INTERNAL_SERVER_ERROR;
        String fallback = "An internal template read error occurred.";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleTemplateReadException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleTemplateReadException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // ------------------- OrganizationIdentifierMismatchException -------------------

    @Test
    void handleOrganizationIdentifierMismatchException_usesExceptionMessage_whenPresent() {
        var ex = new OrganizationIdentifierMismatchException("org mismatch");

        String type   = BackofficeErrorTypes.ORGANIZATION_ID_MISMATCH.getCode();
        String title  = "Unauthorized";
        HttpStatus st = HttpStatus.FORBIDDEN;
        String fallback = "Organization identifier mismatch";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleOrganizationIdentifierMismatchException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "org mismatch"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleOrganizationIdentifierMismatchException_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new OrganizationIdentifierMismatchException((String) null);
        var exBlank = new OrganizationIdentifierMismatchException("");

        String type   = BackofficeErrorTypes.ORGANIZATION_ID_MISMATCH.getCode();
        String title  = "Unauthorized";
        HttpStatus st = HttpStatus.FORBIDDEN;
        String fallback = "Organization identifier mismatch";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleOrganizationIdentifierMismatchException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleOrganizationIdentifierMismatchException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // ------------------- NoSuchEntityException -------------------

    @Test
    void handleNoSuchEntityException_usesExceptionMessage_whenPresent() {
        var ex = new NoSuchEntityException("entity not found");

        String type   = BackofficeErrorTypes.NO_SUCH_ENTITY.getCode();
        String title  = "Not Found";
        HttpStatus st = HttpStatus.NOT_FOUND;
        String fallback = "Requested entity was not found";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleNoSuchEntityException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "entity not found"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleNoSuchEntityException_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new NoSuchEntityException((String) null);
        var exBlank = new NoSuchEntityException(" ");

        String type   = BackofficeErrorTypes.NO_SUCH_ENTITY.getCode();
        String title  = "Not Found";
        HttpStatus st = HttpStatus.NOT_FOUND;
        String fallback = "Requested entity was not found";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleNoSuchEntityException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleNoSuchEntityException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // ------------------- MissingRequiredDataException -------------------

    @Test
    void handleMissingRequiredDataException_usesExceptionMessage_whenPresent() {
        var ex = new MissingRequiredDataException("missing field X");

        String type   = BackofficeErrorTypes.MISSING_REQUIRED_DATA.getCode();
        String title  = "Bad Request";
        HttpStatus st = HttpStatus.BAD_REQUEST;
        String fallback = "Missing required data";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleMissingRequiredDataException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "missing field X"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleMissingRequiredDataException_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new MissingRequiredDataException((String) null);
        var exBlank = new MissingRequiredDataException("");

        String type   = BackofficeErrorTypes.MISSING_REQUIRED_DATA.getCode();
        String title  = "Bad Request";
        HttpStatus st = HttpStatus.BAD_REQUEST;
        String fallback = "Missing required data";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleMissingRequiredDataException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleMissingRequiredDataException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // ------------------- InvalidSignatureConfigurationException -------------------

    @Test
    void handleInvalidSignatureConfigurationException_usesExceptionMessage_whenPresent() {
        var ex = new InvalidSignatureConfigurationException("bad signature cfg");

        String type   = BackofficeErrorTypes.INVALID_SIGNATURE_CONFIGURATION.getCode();
        String title  = "Bad Request";
        HttpStatus st = HttpStatus.BAD_REQUEST;
        String fallback = "Invalid signature configuration";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidSignatureConfigurationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "bad signature cfg"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleInvalidSignatureConfigurationException_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new InvalidSignatureConfigurationException((String) null);
        var exBlank = new InvalidSignatureConfigurationException("   ");

        String type   = BackofficeErrorTypes.INVALID_SIGNATURE_CONFIGURATION.getCode();
        String title  = "Bad Request";
        HttpStatus st = HttpStatus.BAD_REQUEST;
        String fallback = "Invalid signature configuration";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleInvalidSignatureConfigurationException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleInvalidSignatureConfigurationException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }
}
