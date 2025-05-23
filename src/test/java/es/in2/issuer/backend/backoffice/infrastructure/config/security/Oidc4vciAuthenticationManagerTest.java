package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Oidc4vciAuthenticationManagerTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private Oidc4vciAuthenticationManager authenticationManager;

    private String base64UrlEncode(String str) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void authenticate_withValidToken_returnsAuthentication() throws Exception {
        // Arrange
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        // On the header, the claim 'vc' is included with the array that contains "LEARCredentialMachine"
        String payloadJson = "{\"iat\":1633036800,\"exp\":1633040400,\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String token = header + "." + payload + ".signature";

        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class))).thenReturn(Mono.just(Boolean.TRUE));

        ObjectMapper realMapper = new ObjectMapper();
        Map<String, Object> headersMap = realMapper.readValue(headerJson, Map.class);
        Map<String, Object> claimsMap = realMapper.readValue(payloadJson, Map.class);
        when(objectMapper.readValue(headerJson, Map.class)).thenReturn(headersMap);
        when(objectMapper.readValue(payloadJson, Map.class)).thenReturn(claimsMap);

        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectNextMatches(JwtAuthenticationToken.class::isInstance)
                .verifyComplete();

        verify(jwtService).validateJwtSignatureReactive(any(JWSObject.class));
    }

    @Test
    void authenticate_withInvalidTokenFormat_throwsBadCredentialsException() {
        String token = "invalidToken";
        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof java.text.ParseException &&
                        e.getMessage().equals("Invalid serialized unsecured/JWS/JWE object: Missing part delimiters"))
                .verify();
    }


    @Test
    void authenticate_withInvalidPayloadDecoding_throwsBadCredentialsException() {
        // Arrange
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "invalidPayload";
        String header = base64UrlEncode(headerJson);
        String token = header + "." + payload + ".signature";
        Authentication authentication = new TestingAuthenticationToken(null, token);

        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class))).thenReturn(Mono.just(Boolean.FALSE));

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e ->
                        e instanceof BadCredentialsException &&
                                e.getMessage().equals("Invalid JWT token"))
                .verify();
    }


    @Test
    void authenticate_withjWTServiceFailure_propagatesError() {
        // Arrange
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iat\":1633036800,\"exp\":1633040400,\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String token = header + "." + payload + ".signature";

        RuntimeException verifyException = new RuntimeException("Verification failed");
        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class))).thenReturn(Mono.error(verifyException));

        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e.equals(verifyException))
                .verify();
    }
}