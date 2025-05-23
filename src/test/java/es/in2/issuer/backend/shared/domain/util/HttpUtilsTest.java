package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.AbstractMap;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HttpUtilsTest {

    @Mock
    private WebClient webClient;

    @Mock
    private WebClient.Builder webClientBuilder;

    @InjectMocks
    private HttpUtils httpUtils;

    @BeforeEach
    void setUp() {
        when(webClientBuilder.build()).thenReturn(webClient);
        httpUtils = new HttpUtils(webClientBuilder);
    }

    @Test
    void testGetRequest() {
        String url = "https://example.com";
        List<Map.Entry<String, String>> headers = Collections.emptyList();
        String responseBody = "MockedResponse";

        WebClient.RequestHeadersUriSpec requestHeadersUriSpec = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec<?> requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(url)).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.headers(any(Consumer.class))).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.onStatus(any(), any())).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just(responseBody));

        Mono<String> result = httpUtils.getRequest(url, headers);

        StepVerifier.create(result)
                .expectNext(responseBody)
                .verifyComplete();
    }

    @Test
    void testGetRequestErrorStatus() {
        //Arrange
        String url = "https://example.com";
        List<Map.Entry<String, String>> headers = Collections.emptyList();

        WebClient.RequestHeadersUriSpec requestHeadersUriSpec = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec<?> requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
        ClientResponse clientResponse = mock(ClientResponse.class);

        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(url)).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.headers(any(Consumer.class))).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.onStatus(argThat(predicate -> predicate.test(HttpStatus.BAD_REQUEST)), any())).thenAnswer(invocation -> {
            Function<ClientResponse, Mono<? extends Throwable>> function = invocation.getArgument(1);
            return function.apply(clientResponse);
        });

        // Act & Assert
        assertThrows(RuntimeException.class, () -> httpUtils.getRequest(url, headers).block());
    }


    @Test
    void testPostRequest() {
        String url = "https://example.com";
        List<Map.Entry<String, String>> headers = Collections.emptyList();
        String responseBody = "MockedResponse";

        String body = "MockedBody";

        WebClient.RequestBodyUriSpec requestBodyUriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec requestBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(url)).thenReturn(requestBodySpec);
        when(requestBodySpec.headers(any())).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(body)).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.onStatus(any(), any())).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just(responseBody));

        Mono<String> result = httpUtils.postRequest(url, headers, body);

        StepVerifier.create(result)
                .expectNext(responseBody)
                .verifyComplete();
    }

    @Test
    void testPostRequestErrorStatus() {
        String url = "https://example.com";
        List<Map.Entry<String, String>> headers = Collections.emptyList();

        String body = "MockedBody";

        WebClient.RequestBodyUriSpec requestBodyUriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec requestBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
        ClientResponse clientResponse = mock(ClientResponse.class);

        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(url)).thenReturn(requestBodySpec);
        when(requestBodySpec.headers(any())).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(body)).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.onStatus(argThat(predicate -> predicate.test(HttpStatus.BAD_REQUEST)), any())).thenAnswer(invocation -> {
            Function<ClientResponse, Mono<? extends Throwable>> function = invocation.getArgument(1);
            return function.apply(clientResponse);
        });

        // Act & Assert
        assertThrows(RuntimeException.class, () -> httpUtils.postRequest(url, headers, body));
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "http://example.com", "https://example.com"})
    void ensureUrlHasProtocol_ReturnsUrlWithHttpsProtocol(String url) {
        // When
        String result = HttpUtils.ensureUrlHasProtocol(url);

        // Then
        if (url.startsWith("http://")) {
            assertEquals(url, result);
        } else if (url.startsWith("https://")) {
            assertEquals(url, result);
        } else {
            assertEquals("https://" + url, result);
        }
    }

    @ParameterizedTest
    @NullSource
    void ensureUrlHasProtocol_NullInput_ReturnsNull(String url) {
        // When
        String result = HttpUtils.ensureUrlHasProtocol(url);

        // Then
        assertNull(result);
    }

    @Test
    void testPrepareHeadersWithAuth() {
        // Arrange
        String token = "test-token";
        Map.Entry<String, String> expectedHeader = new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + token);

        // Act
        Mono<List<Map.Entry<String, String>>> result = httpUtils.prepareHeadersWithAuth(token);

        // Assert
        StepVerifier.create(result)
                .assertNext(headers -> {
                    assertEquals(1, headers.size());
                    assertEquals(expectedHeader, headers.get(0));
                })
                .verifyComplete();
    }

}