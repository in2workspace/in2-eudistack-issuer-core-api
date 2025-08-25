package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
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
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationManagerTest {

    @Mock
    private VerifierService verifierService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private JWTService jwtService;

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private CustomAuthenticationManager authenticationManager;

    private String base64UrlEncode(String str) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }
    private String buildToken(String headerJson, String payloadJson) {
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String signature = base64UrlEncode("fake-signature");
        return header + "." + payload +"." + signature;
    }

    // Helper para mockear ObjectMapper
    private void prepareObjectMapper(String headerJson, String payloadJson) throws Exception {
        ObjectMapper realMapper = new ObjectMapper();
        Map<String, Object> headersMap = realMapper.readValue(headerJson, Map.class);
        Map<String, Object> claimsMap = realMapper.readValue(payloadJson, Map.class);

        when(objectMapper.readValue(headerJson, Map.class)).thenReturn(headersMap);
        when(objectMapper.readValue(payloadJson, Map.class)).thenReturn(claimsMap);

        if (claimsMap.containsKey("vc")) {
            String vcJson = realMapper.writeValueAsString(claimsMap.get("vc"));
            when(objectMapper.writeValueAsString(claimsMap.get("vc"))).thenReturn(vcJson);
            JsonNode vcNode = realMapper.readTree(vcJson);
            when(objectMapper.readTree(vcJson)).thenReturn(vcNode);
        }
    }

    @Test
    void authenticate_withValidVerifierToken_returnsAuthentication() throws Exception {
        // Arrange
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800,\"exp\":" + (Instant.now().getEpochSecond() + 3600) + ",\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getVerifierUrl()).thenReturn("http://verifier.local");
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        prepareObjectMapper(headerJson, payloadJson);

        Authentication authentication = new TestingAuthenticationToken(null, token);
        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);
        // Assert
        StepVerifier.create(result)
                .expectNextMatches(JwtAuthenticationToken.class::isInstance)
                .verifyComplete();

        verify(verifierService).verifyToken(token);
    }

    @Test
    void authenticate_withInvalidTokenFormat_throwsBadCredentialsException() {
        String token = "invalidToken";
        Authentication authentication = new TestingAuthenticationToken(null, token);
        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        e.getMessage().equals("Invalid JWT token format"))
                .verify();
    }

    @Test
    void authenticate_withMissingVcClaim_throwsBadCredentialsException() throws Exception {
        // Arrange
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800,\"exp\":1633040400}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getVerifierUrl()).thenReturn("http://verifier.local");
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());
        prepareObjectMapper(headerJson, payloadJson);

        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        e.getMessage().equals("The 'vc' claim is required but not present."))
                .verify();
    }

    @Test
    void authenticate_withInvalidVcType_throwsBadCredentialsException() throws Exception {
        // Arrange
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800,\"exp\":1633040400,\"vc\":{\"type\":[\"SomeOtherType\"]}}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getVerifierUrl()).thenReturn("http://verifier.local");
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());
        prepareObjectMapper(headerJson, payloadJson);

        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        e.getMessage().equals("Credential type required: LEARCredentialMachine."))
                .verify();
    }

    @Test
    void authenticate_withInvalidPayloadDecoding_throwsBadCredentialsException() throws JsonProcessingException {
        // Arrange
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String header = base64UrlEncode(headerJson);
        String payload = "invalidPayload";
        String token = header + "." + payload + ".signature"; // este sigue forzado para romper decode

        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorSatisfies(e -> {
                    // Final error
                    assert e instanceof BadCredentialsException;
                    assert e.getMessage().equals("Unable to parse JWT claims");
                    // Root cause
                    assert e.getCause() instanceof java.text.ParseException;
                })
                .verify();
    }


    @Test
    void authenticate_withVerifierServiceFailure_propagatesError() {
        // Arrange
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"exp\":1633040400,\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String token = buildToken(headerJson, payloadJson);

        RuntimeException verifyException = new RuntimeException("Verification failed");

        when(appConfig.getVerifierUrl()).thenReturn("http://verifier.local");
        when(verifierService.verifyToken(token)).thenReturn(Mono.error(verifyException));

        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e.equals(verifyException))
                .verify();
    }

    @Test
    void authenticate_withValidKeycloakToken_returnsAuthentication() throws Exception {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"https://keycloak.local\",\"iat\":1633036800,\"exp\":"
                + (Instant.now().getEpochSecond() + 3600)
                + ",\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String token = buildToken(headerJson, payloadJson);

        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class)))
                .thenReturn(Mono.just(true));

        prepareObjectMapper(headerJson, payloadJson);

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectNextMatches(JwtAuthenticationToken.class::isInstance)
                .verifyComplete();
    }

    @Test
    void authenticate_withKeycloakToken_missingVcClaim_throwsBadCredentialsException() throws Exception {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"https://keycloak.local\",\"iat\":1633036800,\"exp\":" + (Instant.now().getEpochSecond() + 3600) + "}";
        String token = buildToken(headerJson, payloadJson);


        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class)))
                .thenReturn(Mono.just(true));


        prepareObjectMapper(headerJson, payloadJson);

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        e.getMessage().equals("The 'vc' claim is required but not present."))
                .verify();
    }

    @Test
    void authenticate_withKeycloakToken_invalidVcType_throwsBadCredentialsException() throws Exception {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"https://keycloak.local\",\"iat\":1633036800,\"exp\":" + (Instant.now().getEpochSecond() + 3600) + ",\"vc\":{\"type\":[\"OtherType\"]}}";
        String token = buildToken(headerJson, payloadJson);

        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class)))
                .thenReturn(Mono.just(true));


        prepareObjectMapper(headerJson, payloadJson);

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        e.getMessage().equals("Credential type required: LEARCredentialMachine."))
                .verify();
    }

}