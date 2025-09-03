package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationManagerTest {

    @Mock
    private VerifierService verifierService;

    @Mock
    private JWTService jwtService;

    @Mock
    private AppConfig appConfig;

    private CustomAuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        authenticationManager = new CustomAuthenticationManager(
                verifierService,
                new ObjectMapper(),
                appConfig,
                jwtService
        );
    }

    private String base64UrlEncode(String str) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }

    private String buildToken(String headerJson, String payloadJson) {
        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);
        String signature = base64UrlEncode("fake-signature");
        return header + "." + payload + "." + signature;
    }

    @Test
    void authenticate_withValidVerifierToken_returnsAuthentication() {
        // Arrange
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800," +
                "\"exp\":" + (Instant.now().getEpochSecond() + 3600) + "," +
                "\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getVerifierUrl()).thenReturn("http://verifier.local");
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        Authentication authentication = new TestingAuthenticationToken(null, token);

        // Act
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectNextMatches(JwtAuthenticationToken.class::isInstance)
                .verifyComplete();
    }

    @Test
    void authenticate_withInvalidTokenFormat_throwsBadCredentialsException() {
        String token = "invalidToken";
        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Invalid JWT token format".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_withMissingVcClaim_throwsBadCredentialsException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800,\"exp\":1633040400}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getVerifierUrl()).thenReturn("http://verifier.local");
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "The 'vc' claim is required but not present.".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_withInvalidVcType_throwsBadCredentialsException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"iat\":1633036800,\"exp\":1633040400," +
                "\"vc\":{\"type\":[\"SomeOtherType\"]}}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getVerifierUrl()).thenReturn("http://verifier.local");
        when(verifierService.verifyToken(token)).thenReturn(Mono.empty());

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Credential type required: LEARCredentialMachine.".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_withInvalidPayloadDecoding_throwsBadCredentialsException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String header = base64UrlEncode(headerJson);
        String payload = "invalidPayload"; // no és base64url-JSON
        String token = header + "." + payload + ".signature";

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Unable to parse JWT claims".equals(e.getMessage()))
                .verify();
    }

    @Test
    void authenticate_withVerifierServiceFailure_wrapsInAuthenticationServiceException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://verifier.local\",\"exp\":1633040400," +
                "\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String token = buildToken(headerJson, payloadJson);

        RuntimeException verifyException = new RuntimeException("Verification failed");

        when(appConfig.getVerifierUrl()).thenReturn("http://verifier.local");
        when(verifierService.verifyToken(token)).thenReturn(Mono.error(verifyException));

        Authentication authentication = new TestingAuthenticationToken(null, token);

        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorSatisfies(e -> {
                    assert e instanceof AuthenticationServiceException;
                    AuthenticationServiceException ase = (AuthenticationServiceException) e;
                    assert "Verification failed".equals(ase.getMessage());
                    assert ase.getCause() == verifyException;
                })
                .verify();
    }

    @Test
    void authenticate_withValidKeycloakToken_returnsAuthentication() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://issuer.local\",\"iat\":1633036800,\"exp\":" +
                (Instant.now().getEpochSecond() + 3600) + "," +
                "\"vc\":{\"type\":[\"LEARCredentialMachine\"]}}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getIssuerBackendUrl()).thenReturn("http://issuer.local");
        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class)))
                .thenReturn(Mono.just(true));

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectNextMatches(JwtAuthenticationToken.class::isInstance)
                .verifyComplete();
    }

    @Test
    void authenticate_withKeycloakToken_missingVcClaim_returnsAuthentication() {
       String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://issuer.local\",\"iat\":1633036800,\"exp\":" +
                (Instant.now().getEpochSecond() + 3600) + "}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getIssuerBackendUrl()).thenReturn("http://issuer.local");
        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class)))
                .thenReturn(Mono.just(true));

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectNextMatches(JwtAuthenticationToken.class::isInstance)
                .verifyComplete();
    }

    @Test
    void authenticate_withKeycloakToken_invalidVcType_returnsAuthentication() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://issuer.local\",\"iat\":1633036800,\"exp\":" +
                (Instant.now().getEpochSecond() + 3600) + ",\"vc\":{\"type\":[\"OtherType\"]}}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getIssuerBackendUrl()).thenReturn("http://issuer.local");
        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class)))
                .thenReturn(Mono.just(true));

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectNextMatches(JwtAuthenticationToken.class::isInstance)
                .verifyComplete();
    }

    @Test
    void authenticate_withKeycloakToken_invalidSignature_throwsBadCredentialsException() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"iss\":\"http://issuer.local\",\"iat\":1633036800,\"exp\":" +
                (Instant.now().getEpochSecond() + 3600) + "}";
        String token = buildToken(headerJson, payloadJson);

        when(appConfig.getIssuerBackendUrl()).thenReturn("http://issuer.local");
        when(jwtService.validateJwtSignatureReactive(any(JWSObject.class)))
                .thenReturn(Mono.just(false));

        Authentication authentication = new TestingAuthenticationToken(null, token);
        Mono<Authentication> result = authenticationManager.authenticate(authentication);

        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof BadCredentialsException &&
                        "Invalid JWT signature".equals(e.getMessage()))
                .verify();
    }
}
