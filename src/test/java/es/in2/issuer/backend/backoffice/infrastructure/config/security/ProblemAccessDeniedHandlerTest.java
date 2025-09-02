package es.in2.issuer.backend.backoffice.infrastructure.config.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.infrastructure.config.security.SecurityProblemResolver.ProblemSpec;
import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import org.springframework.core.io.buffer.DataBufferUtils;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ProblemAccessDeniedHandlerTest {

    private ObjectMapper objectMapper;
    private ErrorResponseFactory errorResponseFactory;
    private SecurityProblemResolver resolver;

    private ProblemAccessDeniedHandler handler;

    @BeforeEach
    void setUp() {
        objectMapper = mock(ObjectMapper.class);
        errorResponseFactory = mock(ErrorResponseFactory.class);
        resolver = mock(SecurityProblemResolver.class);
        handler = new ProblemAccessDeniedHandler(objectMapper, errorResponseFactory, resolver);
    }

    @Test
    void handle_writesProblemJson_whenObjectMapperSucceeds() throws Exception {
        // given
        AccessDeniedException ex = new AccessDeniedException("nope");
        ProblemSpec spec = new ProblemSpec(
                "access.default",
                "Forbidden",
                HttpStatus.FORBIDDEN,
                "Access denied"
        );
        when(resolver.resolve(ex, false)).thenReturn(spec);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/secure").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GlobalErrorMessage body = new GlobalErrorMessage(
                spec.type(), spec.title(), spec.status().value(), "nope", "inst-abc"
        );
        when(errorResponseFactory.handleWithNow(eq(ex), any(ServerHttpRequest.class),
                eq(spec.type()), eq(spec.title()), eq(spec.status()), eq(spec.fallbackDetail())))
                .thenReturn(body);

        byte[] serialized = ("{\"type\":\"" + spec.type() + "\"," +
                "\"title\":\"" + spec.title() + "\"," +
                "\"status\":" + spec.status().value() + "," +
                "\"detail\":\"nope\",\"instance\":\"inst-abc\"}")
                .getBytes(StandardCharsets.UTF_8);
        when(objectMapper.writeValueAsBytes(body)).thenReturn(serialized);

        // when
        Mono<Void> result = handler.handle(exchange, ex);

        // then
        StepVerifier.create(result).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);

        String responseBody = DataBufferUtils.join(exchange.getResponse().getBody())
                .map(buf -> {
                    byte[] bytes = new byte[buf.readableByteCount()];
                    buf.read(bytes);
                    DataBufferUtils.release(buf);
                    return new String(bytes, StandardCharsets.UTF_8);
                }).block();
        assertThat(responseBody).isEqualTo(new String(serialized, StandardCharsets.UTF_8));

        verify(resolver).resolve(ex, false);

        ArgumentCaptor<ServerHttpRequest> reqCaptor = ArgumentCaptor.forClass(ServerHttpRequest.class);
        verify(errorResponseFactory).handleWithNow(eq(ex), reqCaptor.capture(),
                eq(spec.type()), eq(spec.title()), eq(spec.status()), eq(spec.fallbackDetail()));
        assertThat(reqCaptor.getValue().getPath().value()).isEqualTo("/api/secure");
    }

    @Test
    void handle_writesFallbackJson_whenObjectMapperThrows() throws Exception {
        // given
        AccessDeniedException ex = new AccessDeniedException("denied");
        ProblemSpec spec = new ProblemSpec(
                "access.default",
                "Forbidden",
                HttpStatus.FORBIDDEN,
                "Access denied"
        );
        when(resolver.resolve(ex, false)).thenReturn(spec);

        MockServerHttpRequest request = MockServerHttpRequest.get("/only-admin").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GlobalErrorMessage body = new GlobalErrorMessage(
                spec.type(), spec.title(), spec.status().value(), "denied", "inst-999"
        );
        when(errorResponseFactory.handleWithNow(eq(ex), any(ServerHttpRequest.class),
                anyString(), anyString(), any(HttpStatus.class), anyString()))
                .thenReturn(body);

        when(objectMapper.writeValueAsBytes(any())).thenThrow(new RuntimeException("serialize boom"));

        // when
        Mono<Void> result = handler.handle(exchange, ex);

        // then
        StepVerifier.create(result).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);

        String responseBody = DataBufferUtils.join(exchange.getResponse().getBody())
                .map(buf -> {
                    byte[] bytes = new byte[buf.readableByteCount()];
                    buf.read(bytes);
                    DataBufferUtils.release(buf);
                    return new String(bytes, StandardCharsets.UTF_8);
                }).block();

        assertThat(responseBody).isEqualTo("{\"title\":\"Forbidden\",\"status\":403}");

        verify(resolver).resolve(ex, false);
        verify(errorResponseFactory).handleWithNow(eq(ex), any(ServerHttpRequest.class),
                eq(spec.type()), eq(spec.title()), eq(spec.status()), eq(spec.fallbackDetail()));
    }
}
