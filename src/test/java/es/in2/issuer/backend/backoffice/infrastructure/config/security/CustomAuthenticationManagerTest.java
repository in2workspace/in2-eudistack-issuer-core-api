package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
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

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationManagerTest {

    @Mock
    private VerifierService verifierService;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private CustomAuthenticationManager authenticationManager;

    private String base64UrlEncode(String str) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void authenticate_withValidToken_returnsAuthentication() throws Exception {
        // Arrange
        String headerJson = "{\"alg\":\"none\"}";
        // On the header, the claim 'vc' is included with the array that contains "LEARCredentialMachine"
        String payloadJson = "{\"iat\":1633036800,\"exp\":1633040400,\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String token = header + "." + payload + ".signature";

        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        ObjectMapper realMapper = new ObjectMapper();
        Map<String, Object> headersMap = realMapper.readValue(headerJson, Map.class);
        Map<String, Object> claimsMap = realMapper.readValue(payloadJson, Map.class);
        when(objectMapper.readValue(headerJson, Map.class)).thenReturn(headersMap);
        when(objectMapper.readValue(payloadJson, Map.class)).thenReturn(claimsMap);

        String vcJson = realMapper.writeValueAsString(claimsMap.get("vc"));
        when(objectMapper.writeValueAsString(claimsMap.get("vc"))).thenReturn(vcJson);
        JsonNode vcNode = realMapper.readTree(vcJson);
        when(objectMapper.readTree(vcJson)).thenReturn(vcNode);

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
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

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
        String headerJson = "{\"alg\":\"none\"}";
        String payloadJson = "{\"iat\":1633036800,\"exp\":1633040400}";
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String token = header + "." + payload + ".signature";

        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

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
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        e.getMessage().equals("The 'vc' claim is required but not present."))
                .verify();
    }

    @Test
    void authenticate_withInvalidVcType_throwsBadCredentialsException() throws Exception {
        // Arrange
        String headerJson = "{\"alg\":\"none\"}";
        String payloadJson = "{\"iat\":1633036800,\"exp\":1633040400,\"vc\":{\"type\":[\"SomeOtherType\"]}}";
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String token = header + "." + payload + ".signature";

        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        ObjectMapper realMapper = new ObjectMapper();
        Map<String, Object> headersMap = realMapper.readValue(headerJson, Map.class);
        Map<String, Object> claimsMap = realMapper.readValue(payloadJson, Map.class);
        when(objectMapper.readValue(headerJson, Map.class)).thenReturn(headersMap);
        when(objectMapper.readValue(payloadJson, Map.class)).thenReturn(claimsMap);

        String vcJson = realMapper.writeValueAsString(claimsMap.get("vc"));
        when(objectMapper.writeValueAsString(claimsMap.get("vc"))).thenReturn(vcJson);
        JsonNode vcNode = realMapper.readTree(vcJson);
        when(objectMapper.readTree(vcJson)).thenReturn(vcNode);

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
        String header = base64UrlEncode("{\"alg\":\"none\"}");
        String payload = "invalidPayload";
        String token = header + "." + payload + ".signature";
        Authentication authentication = new TestingAuthenticationToken(null, token);

        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());
        when(objectMapper.readValue("{\"alg\":\"none\"}", Map.class))
                .thenReturn(Map.of("alg", "none"));

        String payloadJson;
        try {
            payloadJson = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        } catch (Exception e) {
            payloadJson = "";
        }
        when(objectMapper.readValue(payloadJson, Map.class))
                .thenThrow(new BadCredentialsException("Invalid JWT payload format"));

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e ->
                        e instanceof BadCredentialsException &&
                                e.getMessage().equals("Invalid JWT payload format"))
                .verify();
    }


    @Test
    void authenticate_withVerifierServiceFailure_propagatesError() {
        // Arrange
        String headerJson = "{\"alg\":\"none\"}";
        String payloadJson = "{\"iat\":1633036800,\"exp\":1633040400,\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String token = header + "." + payload + ".signature";

        RuntimeException verifyException = new RuntimeException("Verification failed");
        when(verifierService.verifyToken(token)).thenReturn(Mono.error(verifyException));

        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e.equals(verifyException))
                .verify();
    }
}