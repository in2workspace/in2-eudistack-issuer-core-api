package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTClaimMissingException;
import es.in2.issuer.backend.shared.domain.exception.JWTCreationException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.infrastructure.crypto.CryptoComponent;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
        JWSObject jwsObject = JWSObject.parse(token);

        Mono<Boolean> result = jwtService.validateJwtSignatureReactive(jwsObject);

        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void validateJwtSignatureReactive_shouldReturn_False() {
        JWSObject jwsObjectMock = mock(JWSObject.class);
        JWSHeader headerMock = mock(JWSHeader.class);
        when(jwsObjectMock.getHeader()).thenReturn(headerMock);
        when(headerMock.getKeyID()).thenReturn("did:key:zDnaef3ThjkPMi5tb6AhLJ4Tu8Zy3mhGQJbfT8axhHsH7SDda");

        Mono<Boolean> result = jwtService.validateJwtSignatureReactive(jwsObjectMock);

        StepVerifier.create(result)
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    void validateJwtSignatureReactive_invalidSignature_with_pad_shouldReturn_IllegalArgumentException() {
        JWSObject jwsObjectMock = mock(JWSObject.class);
        JWSHeader headerMock = mock(JWSHeader.class);
        when(jwsObjectMock.getHeader()).thenReturn(headerMock);
        when(headerMock.getKeyID()).thenReturn("did:key#testEncodedKey");

        Mono<Boolean> result = jwtService.validateJwtSignatureReactive(jwsObjectMock);

        StepVerifier.create(result)
                .expectErrorMatches(IllegalArgumentException.class::isInstance)
                .verify();
    }

    @Test
    void validateJwtSignatureReactive_invalidSignature_no_pad_shouldReturn_IllegalArgumentException() {
        JWSObject jwsObjectMock = mock(JWSObject.class);
        JWSHeader headerMock = mock(JWSHeader.class);
        when(jwsObjectMock.getHeader()).thenReturn(headerMock);
        when(headerMock.getKeyID()).thenReturn("did:key:testEncodedKey");

        Mono<Boolean> result = jwtService.validateJwtSignatureReactive(jwsObjectMock);

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

}
