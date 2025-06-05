package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.text.ParseException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AccessTokenWorkflowImplTest {

    @Mock
    private SignedJWT mockSignedJwt;
    @Mock
    private ObjectMapper mockObjectMapper;
    @InjectMocks
    private AccessTokenServiceImpl accessTokenServiceImpl;

    @Test
    void testGetCleanBearerToken_Valid() {
        String validHeader = "Bearer validToken123";
        Mono<String> result = accessTokenServiceImpl.getCleanBearerToken(validHeader);
        StepVerifier.create(result)
                .expectNext("validToken123")
                .verifyComplete();
    }

    @Test
    void testGetCleanBearerToken_Invalid() {
        String invalidHeader = "invalidToken123";
        Mono<String> result = accessTokenServiceImpl.getCleanBearerToken(invalidHeader);
        StepVerifier.create(result)
                .expectNext(invalidHeader)
                .verifyComplete();
    }

    @Test
    void testGetUserIdFromHeader_Valid() throws Exception {
        String validHeader = "Bearer token";
        String expectedUserId = "userId123";
        String jwtPayload = "{\"sub\":\"" + expectedUserId + "\"}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            SignedJWT signedJWT = mock(SignedJWT.class);
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(signedJWT);
            when(signedJWT.getPayload()).thenReturn(new Payload(jwtPayload));

            ObjectMapper mapper = new ObjectMapper();
            JsonNode payloadJson = mapper.readTree(jwtPayload);
            when(signedJWT.getPayload()).thenReturn(new Payload(payloadJson.toString()));

            Mono<String> result = accessTokenServiceImpl.getUserId(validHeader);

            StepVerifier.create(result)
                    .expectNext(expectedUserId)
                    .verifyComplete();
        }
    }

    @Test
    void testGetUserIdFromHeader_ThrowsParseException() {
        String invalidHeader = "Bearer invalidToken";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString()))
                    .thenThrow(new ParseException("Invalid token", 0));

            Mono<String> result = accessTokenServiceImpl.getUserId(invalidHeader);

            StepVerifier.create(result)
                    .expectError(ParseException.class)
                    .verify();
        }
    }

    @Test
    void testGetOrganizationId_ValidToken() throws JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String expectedOrganizationId = "org123";
        String jwtPayload = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organizationIdentifier\":\"" + expectedOrganizationId + "\"}}}}}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);


            Mono<String> result = accessTokenServiceImpl.getOrganizationId("Bearer " + validJwtToken);

            StepVerifier.create(result)
                    .expectNext(expectedOrganizationId)
                    .verifyComplete();
        }
    }

    @Test
    void testGetOrganizationId_InvalidToken() {
        String invalidJwtToken = "invalid-jwt-token";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenThrow(new ParseException("Invalid token", 0));

            Mono<String> result = accessTokenServiceImpl.getOrganizationId("Bearer " + invalidJwtToken);

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

    @Test
    void testGetOrganizationIdFromCurrentSession_ValidToken() throws ParseException, JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String expectedOrganizationId = "org123";
        String jwtPayload = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organizationIdentifier\":\"" + expectedOrganizationId + "\"}}}}}";

        Jwt jwt = Jwt.withTokenValue(validJwtToken).header("alg", "HS256").claim("organizationIdentifier", expectedOrganizationId).build();
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt);
        SecurityContext securityContext = new SecurityContextImpl(jwtAuthenticationToken);

        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class);
             MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {

            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.just(securityContext));

            // Create a JWSHeader and JWTClaimsSet from the payload
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSHeader.parse("{\"alg\":\"HS256\"}")).build();
            JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(jwtPayload);
            SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

            mockedJwtStatic.when(() -> SignedJWT.parse(validJwtToken)).thenReturn(signedJWT);
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectNext(expectedOrganizationId)
                    .verifyComplete();
        }
    }

    @Test
    void testGetOrganizationIdFromCurrentSession_InvalidToken() {
        String invalidJwtToken = "invalid-jwt-token";

        // Creamos un JWT con una reclamación mínima
        Jwt jwt = Jwt.withTokenValue(invalidJwtToken)
                .header("alg", "none")
                .claim("sub", "subject")
                .build();

        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt);
        SecurityContext securityContext = new SecurityContextImpl(jwtAuthenticationToken);

        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class);
             MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {

            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.just(securityContext));

            mockedJwtStatic.when(() -> SignedJWT.parse(invalidJwtToken)).thenThrow(new ParseException("Invalid token", 0));

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }


    @Test
    void testGetOrganizationIdFromCurrentSession_EmptyToken() {
        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class)) {
            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.empty());

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

    @Test
    void testGetMandateeEmail_Valid() throws Exception {
        String validJwtToken = "header.payload.signature";
        String expectedEmail = "user@example.com";
        String jwtPayload = "{"
                + "\"vc\":{"
                +     "\"credentialSubject\":{"
                +         "\"mandate\":{"
                +             "\"mandatee\":{"
                +                 "\"email\":\"" + expectedEmail + "\""
                +             "}"
                +         "}"
                +     "}"
                + "}"
                + "}";

        try (MockedStatic<SignedJWT> jwtStatic = mockStatic(SignedJWT.class)) {
            jwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            ObjectMapper realMapper = new ObjectMapper();
            JsonNode tree = realMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(tree);

            Mono<String> result = accessTokenServiceImpl.getMandateeEmail("Bearer " + validJwtToken);

            StepVerifier.create(result)
                    .expectNext(expectedEmail)
                    .verifyComplete();
        }
    }

    @Test
    void testGetMandateeEmail_InvalidToken() {
        String invalidJwtToken = "bad.token.here";

        try (MockedStatic<SignedJWT> jwtStatic = mockStatic(SignedJWT.class)) {
            jwtStatic.when(() -> SignedJWT.parse(anyString()))
                    .thenThrow(new ParseException("Invalid token", 0));

            Mono<String> result = accessTokenServiceImpl.getMandateeEmail("Bearer " + invalidJwtToken);

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

    @Test
    void testGetMandateeEmail_InvalidJson() throws Exception {
        String validJwtToken = "header.payload.signature";
        String badJson = "{\"vc\":{}}";

        try (MockedStatic<SignedJWT> jwtStatic = mockStatic(SignedJWT.class)) {
            jwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(badJson));
            when(mockObjectMapper.readTree(badJson))
                    .thenThrow(new JsonProcessingException("Bad JSON") {});

            Mono<String> result = accessTokenServiceImpl.getMandateeEmail("Bearer " + validJwtToken);

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

}