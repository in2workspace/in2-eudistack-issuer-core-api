package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTClaimMissingException;
import es.in2.issuer.backend.shared.domain.exception.JWTCreationException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.infrastructure.crypto.CryptoComponent;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JWTServiceImplTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CryptoComponent cryptoComponent;

    @InjectMocks
    private JWTServiceImpl jwtService;

    @Test
    void generateJWT_throws_JWTCreationException() throws JsonProcessingException {
        String payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";

        ECKey ecKey = mock(ECKey.class);
        when(ecKey.getKeyID()).thenReturn("testKeyID");
        when(ecKey.getCurve()).thenReturn(Curve.P_256);
        when(cryptoComponent.getECKey()).thenReturn(ecKey);

        JsonNode mockJsonNode = mock(JsonNode.class);
        when(objectMapper.readTree(payload)).thenReturn(mockJsonNode);

        Map<String, Object> claimsMap  = new HashMap<>();
        claimsMap .put("sub", "1234567890");
        claimsMap .put("name", "John Doe");
        claimsMap .put("iat", 1516239022);
        when(objectMapper.convertValue(any(JsonNode.class), any(TypeReference.class))).thenReturn(claimsMap);

        assertThrows(JWTCreationException.class, () -> jwtService.generateJWT(payload));
    }
    @Test
    void validateJwtSignatureReactive_validSignature_shouldReturnTrue() throws Exception {
        String token = "eyJraWQiOiJkaWQ6a2V5OnpEbmFlZjZUaGprUE1pNXRiNkFoTEo4VHU4WnkzbWhHUUpiZlQ4YXhoSHNIN1NEZHoiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlZjZUaGprUE1pNXRiNkFoTEo4VHU4WnkzbWhHUUpiZlQ4YXhoSHNIN1NEZHoiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlZjZUaGprUE1pNXRiNkFoTEo4VHU4WnkzbWhHUUpiZlQ4YXhoSHNIN1NEZHoiLCJleHAiOjE3NjAwNzkxMzQsImlhdCI6MTcyNTk1MTEzNH0.5dHXb028Vt9PGai2FBluccJVxO3WXsjnreXGuSOSvUpKzzyCRKYGgWK2nMIBindKonxkOAgUkqaasSYby-gGpg";
        SignedJWT signedJWT = SignedJWT.parse(token);

        Mono<Boolean> result = jwtService.validateJwtSignatureReactive(signedJWT);

        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void validateJwtSignatureReactive_shouldReturn_False() {
        SignedJWT jwtObjectMock = mock(SignedJWT.class);
        JWSHeader headerMock = mock(JWSHeader.class);
        when(jwtObjectMock.getHeader()).thenReturn(headerMock);
        when(headerMock.getKeyID()).thenReturn("did:key:zDnaef3ThjkPMi5tb6AhLJ4Tu8Zy3mhGQJbfT8axhHsH7SDda");

        Mono<Boolean> result = jwtService.validateJwtSignatureReactive(jwtObjectMock);

        StepVerifier.create(result)
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    void validateJwtSignatureReactive_invalidSignature_with_pad_shouldReturn_IllegalArgumentException() {
        SignedJWT jwtObjectMock = mock(SignedJWT.class);
        JWSHeader headerMock = mock(JWSHeader.class);
        when(jwtObjectMock.getHeader()).thenReturn(headerMock);
        when(headerMock.getKeyID()).thenReturn("did:key#testEncodedKey");

        Mono<Boolean> result = jwtService.validateJwtSignatureReactive(jwtObjectMock);

        StepVerifier.create(result)
                .expectErrorMatches(IllegalArgumentException.class::isInstance)
                .verify();
    }

    @Test
    void validateJwtSignatureReactive_invalidSignature_no_pad_shouldReturn_IllegalArgumentException() {
        SignedJWT jwtObjectMock = mock(SignedJWT.class);
        JWSHeader headerMock = mock(JWSHeader.class);
        when(jwtObjectMock.getHeader()).thenReturn(headerMock);
        when(headerMock.getKeyID()).thenReturn("did:key:testEncodedKey");

        Mono<Boolean> result = jwtService.validateJwtSignatureReactive(jwtObjectMock);

        StepVerifier.create(result)
                .expectErrorMatches(IllegalArgumentException.class::isInstance)
                .verify();
    }

    @Test
    void parseJWT_validToken_shouldReturnSignedJWT() {
        String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        SignedJWT result = jwtService.parseJWT(jwtToken);

        assertNotNull(result);
    }

    @Test
    void parseJWT_invalidToken_shouldThrowJWTParsingException() {
        String invalidToken = "invalid.jwt.token";

        try (var mockStaticSignedJWT = mockStatic(SignedJWT.class)) {
            mockStaticSignedJWT.when(() -> SignedJWT.parse(invalidToken))
                    .thenThrow(new ParseException("Invalid token", 0));

            JWTParsingException exception = assertThrows(JWTParsingException.class, () -> jwtService.parseJWT(invalidToken));

            assertEquals("Error when parsing JWTs", exception.getMessage());
        }
    }

    @Test
    void getPayloadFromSignedJWT_validSignedJWT_shouldReturnPayload() {
        SignedJWT signedJWTMock = mock(SignedJWT.class);
        Payload payloadMock = mock(Payload.class);
        when(signedJWTMock.getPayload()).thenReturn(payloadMock);

        Payload result = jwtService.getPayloadFromSignedJWT(signedJWTMock);

        assertNotNull(result);
        assertEquals(payloadMock, result);
    }

    @Test
    void getClaimFromPayload_validClaim_shouldReturnClaimValue() throws JsonProcessingException {
        Payload payloadMock = mock(Payload.class);
        String claimName = "sub";
        String claimValue = "subject";

        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put(claimName, claimValue);

        when(payloadMock.toJSONObject()).thenReturn(claimsMap);
        when(objectMapper.writeValueAsString(claimValue)).thenReturn(claimValue);

        String result = jwtService.getClaimFromPayload(payloadMock, claimName);

        assertNotNull(result);
        assertEquals(claimValue, result);
    }

    @Test
    void getClaimFromPayload_missingClaim_shouldThrowJWTClaimMissingException() {
        Payload payloadMock = mock(Payload.class);
        String claimName = "sub";

        when(payloadMock.toJSONObject()).thenReturn(new HashMap<>());

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () -> jwtService.getClaimFromPayload(payloadMock, claimName));

        assertEquals(String.format("The '%s' claim is missing or empty in the JWT payload.", claimName), exception.getMessage());
    }

    @Test
    void getExpirationFromToken_token_shouldReturnExpiration() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.E9bQ6QAil4HpH825QC5PtjNGEDQTtMpcj0SO2W8vmag";
        Long expiration = 1516239022L;

        Long result = jwtService.getExpirationFromToken(token);

        assertNotNull(result);
        Assertions.assertEquals(expiration, result);
    }

    @Test
    void getExpirationFromToken_token_shouldThrowJWTClaimMissingExceptionMissingClaim() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A";

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () -> jwtService.getExpirationFromToken(token));

        Assertions.assertEquals("The 'exp' claim is missing in the JWT payload.", exception.getMessage());
    }

    @Test
    void getExpirationFromToken_token_shouldThrowJWTClaimMissingExceptionNotNumeric() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoic3RyaW5nIn0.Ku5X63YN9UGSDkQTcrozyKLfGIcX1kKXaIXh3zl8c-8";

        JWTClaimMissingException exception = assertThrows(JWTClaimMissingException.class, () -> jwtService.getExpirationFromToken(token));

        Assertions.assertEquals("The 'exp' claim is not a valid number in the JWT payload.", exception.getMessage());
    }

    @Test
    void resolvePrincipal_returnsMandateeEmail_whenPresentInVcObject() {
        // Build nested VC as object (no vc_json)
        Map<String, Object> mandatee = new HashMap<>();
        mandatee.put("email", "mandatee@example.com");

        Map<String, Object> mandate = new HashMap<>();
        mandate.put("mandatee", mandatee);

        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("mandate", mandate);

        Map<String, Object> vc = new HashMap<>();
        vc.put("credentialSubject", credentialSubject);

        Map<String, Object> claims = new HashMap<>();
        claims.put("vc", vc);
        claims.put("sub", "subject@example.com"); // should be ignored because mandatee email exists

        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "none"),
                claims
        );

        String principal = jwtService.resolvePrincipal(jwt);
        assertEquals("mandatee@example.com", principal);
    }

    @Test
    void extractMandateeEmail_readsFromVcJson_whenStringifiedJsonProvided() throws Exception {
        // vc_json string provided by the IDP
        String vcJson = "{\"credentialSubject\":{\"mandate\":{\"mandatee\":{\"email\":\"from-vcjson@example.com\"}}}}";

        Map<String, Object> parsed = new HashMap<>();
        Map<String, Object> mandatee = new HashMap<>();
        mandatee.put("email", "from-vcjson@example.com");
        Map<String, Object> mandate = new HashMap<>();
        mandate.put("mandatee", mandatee);
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("mandate", mandate);
        parsed.put("credentialSubject", credentialSubject);

        // Stub ObjectMapper.readValue for vc_json parsing success
        when(objectMapper.readValue(eq(vcJson), any(TypeReference.class))).thenReturn(parsed);

        Map<String, Object> claims = new HashMap<>();
        claims.put("vc_json", vcJson);

        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "none"),
                claims
        );

        Optional<String> email = jwtService.extractMandateeEmail(jwt);
        assertTrue(email.isPresent());
        assertEquals("from-vcjson@example.com", email.get());
    }

    @Test
    void extractMandateeEmail_fallsBackToTopLevelEmail_whenVcMissing() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "top@example.com");
        // no vc, no vc_json

        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "none"),
                claims
        );

        Optional<String> email = jwtService.extractMandateeEmail(jwt);
        assertTrue(email.isPresent());
        assertEquals("top@example.com", email.get());
    }

    @Test
    void resolvePrincipal_returnsAnonymous_whenNoEmailsAndSubjectBlank() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "   "); // blank subject

        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "none"),
                claims
        );

        String principal = jwtService.resolvePrincipal(jwt);
        assertEquals("anonymous", principal);
    }

    @Test
    void resolveVc_returnsEmptyMap_whenVcJsonMalformed() throws Exception {
        String badJson = "{not-a-json";
        // Force ObjectMapper to throw on malformed JSON
        when(objectMapper.readValue(eq(badJson), any(TypeReference.class)))
                .thenThrow(new RuntimeException("boom"));

        Map<String, Object> claims = new HashMap<>();
        claims.put("vc_json", badJson);

        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "none"),
                claims
        );

        // With malformed vc_json and no top-level email, extraction should be empty
        Optional<String> email = jwtService.extractMandateeEmail(jwt);
        assertTrue(email.isEmpty());
    }
    @Test
    void validateJwtSignatureWithJwkReactive_ES256_validSignature_returnsTrue() throws Exception {
        // Generate EC P-256 key
        ECKey ecJwk = new ECKeyGenerator(Curve.P_256)
                .keyID("ec-kid-1")
                .generate();

        // Build signed JWT with ES256
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(ecJwk.getKeyID())
                .type(JOSEObjectType.JWT)
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("issuer")
                .subject("subject")
                .issueTime(new Date())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(ecJwk));

        String token = jwt.serialize();

        Map<String, Object> jwkMap = ecJwk.toPublicJWK().toJSONObject();

        Mono<Boolean> result = jwtService.validateJwtSignatureWithJwkReactive(token, jwkMap);

        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void validateJwtSignatureWithJwkReactive_ES256_invalidSignature_returnsFalse() throws Exception {

        ECKey signerKey = new ECKeyGenerator(Curve.P_256).keyID("signer").generate();
        ECKey verifierKey = new ECKeyGenerator(Curve.P_256).keyID("verifier").generate();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("signer").build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("s").issueTime(new Date()).build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(signerKey));

        String token = jwt.serialize();
        Map<String, Object> wrongPublicJwkMap = verifierKey.toPublicJWK().toJSONObject();

        Mono<Boolean> result = jwtService.validateJwtSignatureWithJwkReactive(token, wrongPublicJwkMap);

        StepVerifier.create(result)
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    void validateJwtSignatureWithJwkReactive_privateJwk_shouldError() throws Exception {
        ECKey ecJwk = new ECKeyGenerator(Curve.P_256).keyID("ec-private").generate();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("ec-private").build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().issueTime(new Date()).build());
        jwt.sign(new ECDSASigner(ecJwk));
        String token = jwt.serialize();

        Map<String, Object> privateJwkMap = ecJwk.toJSONObject();

        Mono<Boolean> result = jwtService.validateJwtSignatureWithJwkReactive(token, privateJwkMap);

        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ProofValidationException &&
                                err.getMessage().contains("jwk must not contain private key material")
                )
                .verify();
    }



    @Test
    void validateJwtSignatureWithJwkReactive_malformedJwtOrJwk_shouldError() {
        String badJwt = "not-a-jwt";
        Map<String, Object> badJwk = Map.of("kty", "EC"); // missing x/y/crv

        Mono<Boolean> result = jwtService.validateJwtSignatureWithJwkReactive(badJwt, badJwk);

        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ProofValidationException &&
                                err.getMessage().contains("malformed jwt or jwk")
                )
                .verify();
    }
    @Test
    void validateJwtSignatureWithJwkReactive_algMismatch_ecKeyWithEdDsaToken_shouldError_withoutTink() throws Exception {

        String token = dummyJwtWithAlg("EdDSA");

        ECKey ec = new ECKeyGenerator(Curve.P_256).keyID("ec").generate();
        Map<String, Object> ecPublic = ec.toPublicJWK().toJSONObject();

        Mono<Boolean> result = jwtService.validateJwtSignatureWithJwkReactive(token, ecPublic);

        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ProofValidationException &&
                                err.getMessage().contains("invalid_proof: alg not compatible with EC JWK")
                )
                .verify();
    }

    @Test
    void validateJwtSignatureWithJwkReactive_okpEd25519WithEs256Token_shouldError_withoutTink() {

        String token = dummyJwtWithAlg("ES256");

        Map<String, Object> jwkEd25519 = new HashMap<>();
        jwkEd25519.put("kty", "OKP");
        jwkEd25519.put("crv", "Ed25519");
        jwkEd25519.put("x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        Mono<Boolean> result = jwtService.validateJwtSignatureWithJwkReactive(token, jwkEd25519);

        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ProofValidationException &&
                                err.getMessage().contains("invalid_proof: alg not compatible with Ed25519 JWK")
                )
                .verify();
    }


    @Test
    void validateJwtSignatureWithJwkReactive_okpWrongCurve_X25519_shouldError_withoutTink() {
        String token = dummyJwtWithAlg("EdDSA");

        Map<String, Object> x25519PublicJwk = Map.of(
                "kty", "OKP",
                "crv", "X25519",
                "x", "AQIDBAUGBwgJCgsMDQ4PEA"
        );

        Mono<Boolean> result = jwtService.validateJwtSignatureWithJwkReactive(token, x25519PublicJwk);

        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ProofValidationException &&
                                err.getMessage().contains("invalid_proof: only Ed25519 OKP keys are supported for signatures")
                )
                .verify();
    }

    @Test
    void validateJwtSignatureWithJwkReactive_unsupportedKty_shouldError() throws Exception {

        ECKey ecSigner = new ECKeyGenerator(Curve.P_256).keyID("ec").generate();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("ec").build(),
                new JWTClaimsSet.Builder().issueTime(new Date()).build()
        );
        jwt.sign(new ECDSASigner(ecSigner));
        String token = jwt.serialize();

        Map<String, Object> rsaLikeJwk = Map.of(
                "kty", "RSA",
                "n", "AQAB",
                "e", "AQAB"
        );

        Mono<Boolean> result = jwtService.validateJwtSignatureWithJwkReactive(token, rsaLikeJwk);

        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ProofValidationException &&
                                err.getMessage().contains("invalid_proof: jwk kty not supported")
                )
                .verify();
    }

    private static String b64Url(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static String dummyJwtWithAlg(String alg) {
        String header = b64Url("{\"alg\":\"" + alg + "\"}");
        String payload = b64Url("{\"sub\":\"s\"}");
        String sig = "aa";
        return header + "." + payload + "." + sig;
    }


}
