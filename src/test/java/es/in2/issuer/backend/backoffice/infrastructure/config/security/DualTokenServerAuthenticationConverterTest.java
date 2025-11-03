package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;

class DualTokenServerAuthenticationConverterTest {

    private final DualTokenServerAuthenticationConverter converter =
            new DualTokenServerAuthenticationConverter();

    @Test
    void convert_withValidBearerAndIdToken_returnsDualTokenAuth() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/resource")
                .header(HttpHeaders.AUTHORIZATION, "Bearer access-123")
                .header("X-ID-Token", "id-456")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Mono<Authentication> result = converter.convert(exchange);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertTrue(auth instanceof DualTokenAuthentication);
                    DualTokenAuthentication dual = (DualTokenAuthentication) auth;
                    assertEquals("access-123", dual.getAccessToken());
                    assertEquals("id-456", dual.getIdToken());
                    assertEquals("access-123", dual.getCredentials());
                    assertEquals("N/A", dual.getPrincipal());
                    assertFalse(dual.isAuthenticated());
                })
                .verifyComplete();
    }

    @Test
    void convert_withValidBearerAndBlankIdToken_setsIdTokenNull() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/resource")
                .header(HttpHeaders.AUTHORIZATION, "Bearer access-123")
                .header("X-ID-Token", "   ") // blank -> should become null
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(converter.convert(exchange))
                .assertNext(auth -> {
                    DualTokenAuthentication dual = (DualTokenAuthentication) auth;
                    assertEquals("access-123", dual.getAccessToken());
                    assertNull(dual.getIdToken());
                })
                .verifyComplete();
    }

    @Test
    void convert_withLowercaseBearerAndExtraSpaces_trimsAndParses() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/health")
                .header(HttpHeaders.AUTHORIZATION, "bearer    abc123   ")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(converter.convert(exchange))
                .assertNext(auth -> {
                    DualTokenAuthentication dual = (DualTokenAuthentication) auth;
                    assertEquals("abc123", dual.getAccessToken());
                    assertNull(dual.getIdToken());
                })
                .verifyComplete();
    }

    @Test
    void convert_withoutAuthorizationHeader_returnsEmpty() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/no-auth").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(converter.convert(exchange))
                .verifyComplete(); // Mono.empty()
    }

    @Test
    void convert_withNonBearerAuthorization_returnsEmpty() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/basic")
                .header(HttpHeaders.AUTHORIZATION, "Basic Zm9vOmJhcg==")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(converter.convert(exchange))
                .verifyComplete(); // Mono.empty()
    }

    @Test
    void convert_withBearerWithoutToken_allowsEmptyAccessToken() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/edge")
                .header(HttpHeaders.AUTHORIZATION, "Bearer ")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(converter.convert(exchange))
                .assertNext(auth -> {
                    DualTokenAuthentication dual = (DualTokenAuthentication) auth;
                    // substring(7).trim() -> empty string
                    assertEquals("", dual.getAccessToken());
                    assertNull(dual.getIdToken());
                })
                .verifyComplete();
    }
}
