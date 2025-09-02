package es.in2.issuer.backend.shared.infrastructure.controller.error;

import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ErrorResponseFactoryTest {

    private ErrorResponseFactory factory;
    private ServerHttpRequest mockRequest;

    @BeforeEach
    void setUp() {
        factory = new ErrorResponseFactory();
        mockRequest = MockServerHttpRequest.get("/api/test?x=1").build();
    }

    private String invokeResolveDetail(Exception ex, String fallback) throws Exception {
        Method m = ErrorResponseFactory.class.getDeclaredMethod("resolveDetail", Exception.class, String.class);
        m.setAccessible(true);
        return (String) m.invoke(factory, ex, fallback);
    }

    private GlobalErrorMessage invokeBuildError(
            String type, String title, HttpStatus status, String detail, Exception ex
    ) throws Exception {
        Method m = ErrorResponseFactory.class.getDeclaredMethod(
                "buildError",
                String.class, String.class, HttpStatus.class, String.class, Exception.class, ServerHttpRequest.class
        );
        m.setAccessible(true);
        return (GlobalErrorMessage) m.invoke(factory, type, title, status, detail, ex, mockRequest);
    }

    @SuppressWarnings("unchecked")
    private Mono<GlobalErrorMessage> invokeHandleWith(
            Exception ex, String type, String title, HttpStatus status, String fallbackDetail
    ) throws Exception {
        Method m = ErrorResponseFactory.class.getDeclaredMethod(
                "handleWith",
                Exception.class, ServerHttpRequest.class, String.class, String.class, HttpStatus.class, String.class
        );
        m.setAccessible(true);
        return (Mono<GlobalErrorMessage>) m.invoke(factory, ex, mockRequest, type, title, status, fallbackDetail);
    }

    @Test
    void resolveDetail_returnsExceptionMessage_whenPresent() throws Exception {
        Exception ex = new IllegalArgumentException("bad arg");
        String detail = invokeResolveDetail(ex, "fallback");
        assertEquals("bad arg", detail);
    }

    @Test
    void resolveDetail_returnsFallback_whenExceptionMessageIsNullOrBlank() throws Exception {
        Exception ex1 = new RuntimeException((String) null);
        Exception ex2 = new RuntimeException("");
        Exception ex3 = new RuntimeException("   ");

        assertEquals("fallback-1", invokeResolveDetail(ex1, "fallback-1"));
        assertEquals("fallback-2", invokeResolveDetail(ex2, "fallback-2"));
        assertEquals("fallback-3", invokeResolveDetail(ex3, "fallback-3"));
    }

    @Test
    void buildError_populatesFields_andGeneratesUuidInstance() throws Exception {
        String type = "https://example.com/problem";
        String title = "Something went wrong";
        HttpStatus status = HttpStatus.UNPROCESSABLE_ENTITY;
        String detail = "specific detail here";
        Exception ex = new IllegalStateException("boom");

        GlobalErrorMessage msg = invokeBuildError(type, title, status, detail, ex);

        assertNotNull(msg);
        assertEquals(type, msg.type());
        assertEquals(title, msg.title());
        assertEquals(status.value(), msg.status());
        assertEquals(detail, msg.detail());
        assertNotNull(msg.instance());
        assertFalse(msg.instance().isBlank());

        assertDoesNotThrow(() -> UUID.fromString(msg.instance()));
    }

    @Test
    void buildError_generatesDifferentInstanceEachCall() throws Exception {
        GlobalErrorMessage a = invokeBuildError("t1", "title1", HttpStatus.BAD_REQUEST, "d1", new RuntimeException("e1"));
        GlobalErrorMessage b = invokeBuildError("t2", "title2", HttpStatus.BAD_REQUEST, "d2", new RuntimeException("e2"));
        assertNotEquals(a.instance(), b.instance());
    }

    @Test
    void handleWith_usesExceptionMessage_whenPresent() throws Exception {
        Exception ex = new IllegalArgumentException("param missing");
        Mono<GlobalErrorMessage> mono = invokeHandleWith(
                ex,
                "https://example.com/problem",
                "Bad Request",
                HttpStatus.BAD_REQUEST,
                "fallback detail"
        );

        StepVerifier.create(mono)
                .assertNext(msg -> {
                    assertEquals("https://example.com/problem", msg.type());
                    assertEquals("Bad Request", msg.title());
                    assertEquals(HttpStatus.BAD_REQUEST.value(), msg.status());
                    assertEquals("param missing", msg.detail());
                    assertDoesNotThrow(() -> UUID.fromString(msg.instance()));
                })
                .verifyComplete();
    }

    @Test
    void handleWith_usesFallback_whenExceptionMessageNull() throws Exception {
        Exception ex = new RuntimeException((String) null);
        Mono<GlobalErrorMessage> mono = invokeHandleWith(
                ex,
                "https://example.com/problem",
                "Internal Error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "safe default"
        );

        StepVerifier.create(mono)
                .assertNext(msg -> {
                    assertEquals("https://example.com/problem", msg.type());
                    assertEquals("Internal Error", msg.title());
                    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), msg.status());
                    assertEquals("safe default", msg.detail());
                    assertDoesNotThrow(() -> UUID.fromString(msg.instance()));
                })
                .verifyComplete();
    }

    @Test
    void handleWith_isLazyAndBuildsFromSupplier() throws Exception {
        Exception ex = new RuntimeException("on-demand");
        Mono<GlobalErrorMessage> mono = invokeHandleWith(
                ex,
                "type-x",
                "title-x",
                HttpStatus.NOT_FOUND,
                "fallback-x"
        );

        StepVerifier.create(mono)
                .assertNext(msg -> {
                    assertEquals("type-x", msg.type());
                    assertEquals("title-x", msg.title());
                    assertEquals(HttpStatus.NOT_FOUND.value(), msg.status());
                    assertEquals("on-demand", msg.detail());
                })
                .verifyComplete();
    }

    @Test
    void handleWithNow_usesExceptionMessage_whenPresent() {
        Exception ex = new IllegalArgumentException("bad arg");
        GlobalErrorMessage msg = factory.handleWithNow(
                ex,
                mockRequest,
                "https://example.com/problem",
                "Bad Request",
                HttpStatus.BAD_REQUEST,
                "fallback detail"
        );

        assertNotNull(msg);
        assertEquals("https://example.com/problem", msg.type());
        assertEquals("Bad Request", msg.title());
        assertEquals(HttpStatus.BAD_REQUEST.value(), msg.status());
        assertEquals("bad arg", msg.detail()); // fa servir el missatge de l'excepció
        assertNotNull(msg.instance());
        assertDoesNotThrow(() -> UUID.fromString(msg.instance()));
    }

    @Test
    void handleWithNow_usesFallback_whenExceptionMessageNullOrBlank() {
        Exception ex1 = new RuntimeException((String) null);
        Exception ex2 = new RuntimeException("");
        Exception ex3 = new RuntimeException("   ");

        GlobalErrorMessage m1 = factory.handleWithNow(
                ex1, mockRequest, "t", "Title", HttpStatus.INTERNAL_SERVER_ERROR, "fallback-1");
        GlobalErrorMessage m2 = factory.handleWithNow(
                ex2, mockRequest, "t", "Title", HttpStatus.INTERNAL_SERVER_ERROR, "fallback-2");
        GlobalErrorMessage m3 = factory.handleWithNow(
                ex3, mockRequest, "t", "Title", HttpStatus.INTERNAL_SERVER_ERROR, "fallback-3");

        assertEquals("fallback-1", m1.detail());
        assertEquals("fallback-2", m2.detail());
        assertEquals("fallback-3", m3.detail());
        assertDoesNotThrow(() -> UUID.fromString(m1.instance()));
        assertDoesNotThrow(() -> UUID.fromString(m2.instance()));
        assertDoesNotThrow(() -> UUID.fromString(m3.instance()));
    }

}
