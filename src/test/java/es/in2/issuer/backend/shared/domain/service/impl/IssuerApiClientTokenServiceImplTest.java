package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.PreAuthorizationCodeGetException;
import es.in2.issuer.backend.shared.infrastructure.config.AuthServerConfig;
import es.in2.issuer.backend.shared.infrastructure.config.WebClientConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.function.Function;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CONTENT_TYPE_URL_ENCODED_FORM;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

@ExtendWith(MockitoExtension.class)
class IssuerApiClientTokenServiceImplTest {

    @Mock
    private AuthServerConfig authServerConfig;

    @Mock
    private WebClientConfig webClientConfig;

    @Mock
    private WebClient webClient;

    @Mock
    private WebClient.RequestBodyUriSpec requestBodyUriSpec;

    @Mock
    private WebClient.RequestHeadersSpec requestHeadersSpec;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private IssuerApiClientTokenServiceImpl issuerApiClientTokenService;

    @Test
    void testGetClientToken_Success() throws JsonProcessingException {
        //Arrange
        when(authServerConfig.getAuthServerClientId()).thenReturn("clientId");
        when(authServerConfig.getAuthServerUsername()).thenReturn("username");
        when(authServerConfig.getAuthServerUserPassword()).thenReturn("password");
        when(authServerConfig.getTokenUri()).thenReturn("https://auth.server/token");
        when(webClientConfig.commonWebClient()).thenReturn(webClient);
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri("https://auth.server/token")).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.header(CONTENT_TYPE, CONTENT_TYPE_URL_ENCODED_FORM)).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.bodyValue(anyString())).thenReturn(requestHeadersSpec);

        // Configure exchangeToMono to handle the ClientResponse and return a Mono<String>
        when(requestHeadersSpec.exchangeToMono(any())).thenAnswer(invocation -> {
            Function<ClientResponse, Mono<String>> responseHandler = invocation.getArgument(0);
            ClientResponse clientResponse = mock(ClientResponse.class);
            when(clientResponse.statusCode()).thenReturn(HttpStatus.OK);
            when(clientResponse.bodyToMono(String.class)).thenReturn(Mono.just("{\"access_token\":\"dummyToken\"}"));
            return responseHandler.apply(clientResponse);
        });
        when(objectMapper.readValue(anyString(), any(TypeReference.class))).thenReturn(Map.of("access_token", "dummyToken"));

        // Act
        Mono<String> result = issuerApiClientTokenService.getClientToken();

        // Assert
        StepVerifier.create(result)
                .expectNext("dummyToken")
                .verifyComplete();
    }

    @Test
    void testGetClientToken_ClientError() {
        // Arrange
        when(authServerConfig.getAuthServerClientId()).thenReturn("clientId");
        when(authServerConfig.getAuthServerUsername()).thenReturn("username");
        when(authServerConfig.getAuthServerUserPassword()).thenReturn("password");
        when(authServerConfig.getTokenUri()).thenReturn("https://auth.server/token");
        when(webClientConfig.commonWebClient()).thenReturn(webClient);
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri("https://auth.server/token")).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.header(CONTENT_TYPE, CONTENT_TYPE_URL_ENCODED_FORM)).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.bodyValue(anyString())).thenReturn(requestHeadersSpec);

        // Configure exchangeToMono to handle the ClientResponse and return a Mono<ClientResponse>
        when(requestHeadersSpec.exchangeToMono(any())).thenAnswer(invocation -> {
            Function<ClientResponse, Mono<String>> responseHandler = invocation.getArgument(0);
            ClientResponse clientResponse = mock(ClientResponse.class);
            when(clientResponse.statusCode()).thenReturn(HttpStatus.BAD_REQUEST);
            return responseHandler.apply(clientResponse);
        });

        // Act
        Mono<String> result = issuerApiClientTokenService.getClientToken();

        // Assert
        StepVerifier.create(result)
                .expectError(PreAuthorizationCodeGetException.class)
                .verify();
    }


    @Test
    void testGetClientToken_JsonProcessingException() throws JsonProcessingException {
        when(authServerConfig.getAuthServerClientId()).thenReturn("clientId");
        when(authServerConfig.getAuthServerUsername()).thenReturn("username");
        when(authServerConfig.getAuthServerUserPassword()).thenReturn("password");
        when(authServerConfig.getTokenUri()).thenReturn("https://auth.server/token");
        when(webClientConfig.commonWebClient()).thenReturn(webClient);
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri("https://auth.server/token")).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.header(CONTENT_TYPE, CONTENT_TYPE_URL_ENCODED_FORM)).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.bodyValue(anyString())).thenReturn(requestHeadersSpec);

        // Configure exchangeToMono to handle the ClientResponse and return a Mono<ClientResponse>
        when(requestHeadersSpec.exchangeToMono(any())).thenAnswer(invocation -> {
            Function<ClientResponse, Mono<String>> responseHandler = invocation.getArgument(0);
            ClientResponse clientResponse = mock(ClientResponse.class);
            when(clientResponse.statusCode()).thenReturn(HttpStatus.OK);
            when(clientResponse.bodyToMono(String.class)).thenReturn(Mono.just("{\"access_token\":\"dummyToken\"}"));
            return responseHandler.apply(clientResponse);
        });

        // Mocking ObjectMapper to throw JsonProcessingException
        when(objectMapper.readValue(anyString(), any(TypeReference.class))).thenThrow(new JsonProcessingException("error") {
        });

        // Act
        Mono<String> result = issuerApiClientTokenService.getClientToken();

        // Assert
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

}