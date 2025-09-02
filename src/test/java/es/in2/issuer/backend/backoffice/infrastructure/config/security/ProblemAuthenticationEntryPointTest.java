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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import org.springframework.core.io.buffer.DataBufferUtils;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ProblemAuthenticationEntryPointTest {

    private ObjectMapper objectMapper;
    private ErrorResponseFactory errorResponseFactory;
    private SecurityProblemResolver resolver;

    private ProblemAuthenticationEntryPoint entryPoint;

    @BeforeEach
    void setUp() {
        objectMapper = mock(ObjectMapper.class);
        errorResponseFactory = mock(ErrorResponseFactory.class);
        resolver = mock(SecurityProblemResolver.class);
        entryPoint = new ProblemAuthenticationEntryPoint(objectMapper, errorResponseFactory, resolver);
    }

    @Test
    void commence_writesProblemJson_whenObjectMapperSucceeds() throws Exception {
        // given
        AuthenticationException ex = new BadCredentialsException("bad token");
        ProblemSpec spec = new ProblemSpec(
                "auth.invalid_token",
                "Invalid token",
                HttpStatus.UNAUTHORIZED,
                "Invalid token"
        );
        when(resolver.resolve(same(ex), anyBoolean())).thenReturn(spec);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GlobalErrorMessage gem = new GlobalErrorMessage(
                spec.type(), spec.title(), spec.status().value(), "bad token", "instance-123"
        );
        when(errorResponseFactory.handleWithNow(
                same(ex),
                any(ServerHttpRequest.class),
                argThat(s -> s.equals(spec.type())),
                argThat(s -> s.equals(spec.title())),
                argThat(status -> status == spec.status()),
                argThat(s -> s.equals(spec.fallbackDetail()))
        )).thenReturn(gem);

        byte[] serialized = "{\"type\":\"auth.invalid_token\",\"title\":\"Invalid token\",\"status\":401,\"detail\":\"bad token\",\"instance\":\"instance-123\"}"
                .getBytes(StandardCharsets.UTF_8);
        when(objectMapper.writeValueAsBytes(same(gem))).thenReturn(serialized);

        // when
        Mono<Void> result = entryPoint.commence(exchange, ex);

        // then (complete successfully)
        StepVerifier.create(result).verifyComplete();

        // verify status + content-type
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.valueOf("application/problem+json"));

        // verify body content
        String body = DataBufferUtils.join(exchange.getResponse().getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return new String(bytes, StandardCharsets.UTF_8);
                }).block();

        assertThat(body).isEqualTo(new String(serialized, StandardCharsets.UTF_8));

        // verify resolver was called with isAuthenticationPhase=true
        verify(resolver).resolve(ex, true);

        // verify ErrorResponseFactory called with the right args
        ArgumentCaptor<ServerHttpRequest> reqCaptor = ArgumentCaptor.forClass(ServerHttpRequest.class);
        verify(errorResponseFactory).handleWithNow(
                same(ex),
                reqCaptor.capture(),
                argThat(s -> s.equals(spec.type())),
                argThat(s -> s.equals(spec.title())),
                argThat(status -> status == spec.status()),
                argThat(s -> s.equals(spec.fallbackDetail()))
        );
        assertThat(reqCaptor.getValue().getPath().value()).isEqualTo("/api/test");
    }

    @Test
    void commence_writesFallbackJson_whenObjectMapperThrows() throws Exception {
        // given
        AuthenticationException ex = new BadCredentialsException("oops");
        ProblemSpec spec = new ProblemSpec(
                "auth.default",
                "Unauthorized",
                HttpStatus.UNAUTHORIZED,
                "Authentication failed"
        );
        when(resolver.resolve(same(ex), anyBoolean())).thenReturn(spec);

        MockServerHttpRequest request = MockServerHttpRequest.get("/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GlobalErrorMessage gem = new GlobalErrorMessage(
                spec.type(), spec.title(), spec.status().value(), "oops", "inst-999"
        );
        when(errorResponseFactory.handleWithNow(
                same(ex),
                any(ServerHttpRequest.class),
                anyString(),
                anyString(),
                any(HttpStatus.class),
                anyString()
        )).thenReturn(gem);

        // Force ObjectMapper to fail
        when(objectMapper.writeValueAsBytes(any())).thenThrow(new RuntimeException("marshalling error"));

        // when
        Mono<Void> result = entryPoint.commence(exchange, ex);

        // then
        StepVerifier.create(result).verifyComplete();

        // headers
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.valueOf("application/problem+json"));

        // fallback body
        String body = DataBufferUtils.join(exchange.getResponse().getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return new String(bytes, StandardCharsets.UTF_8);
                }).block();

        assertThat(body).isEqualTo("{\"title\":\"Unauthorized\",\"status\":401}");

        verify(resolver).resolve(ex, true);
        verify(errorResponseFactory).handleWithNow(
                same(ex),
                any(ServerHttpRequest.class),
                argThat(s -> s.equals(spec.type())),
                argThat(s -> s.equals(spec.title())),
                argThat(status -> status == spec.status()),
                argThat(s -> s.equals(spec.fallbackDetail()))
        );
    }
}
