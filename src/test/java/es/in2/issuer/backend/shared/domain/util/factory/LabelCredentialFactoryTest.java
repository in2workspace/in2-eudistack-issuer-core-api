package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import es.in2.issuer.backend.shared.domain.exception.CredentialSerializationException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LabelCredentialJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.LabelCredential;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.DefaultSignerConfig; // <-- NEW import
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LabelCredentialFactoryTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private IssuerFactory issuerFactory;

    @Mock
    private AppConfig appConfig;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DefaultSignerConfig defaultSignerConfig; // <-- NEW mock to satisfy constructor

    @InjectMocks
    private LabelCredentialFactory labelCredentialFactory;

    @Test
    void testMapCredentialAndBindIssuerInToTheCredential() throws Exception {

        String procedureId = "procedure-123";
        String credentialJson = "{\"id\":\"urn:uuid:123\"}";
        String testEmail = "test@email.com";

        LabelCredential labelCredential = LabelCredential.builder()
                .id("label-1")
                .type(List.of("gx:LabelCredential"))
                .validFrom(Instant.now().toString())
                .validUntil(Instant.now().plus(1, ChronoUnit.DAYS).toString())
                .credentialSubject(LabelCredential.CredentialSubject.builder().id("subject-1").build())
                .build();

        // ObjectMapper returns our LabelCredential
        when(objectMapper.readValue(credentialJson, LabelCredential.class))
                .thenReturn(labelCredential);

        // Match real invocation: (procedureId, LABEL_CREDENTIAL, email="testEmail")
        when(issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, testEmail))
                .thenReturn(Mono.just(SimpleIssuer.builder().id("issuer-id").build()));

        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
                .thenReturn("{\"mocked\": true}");

        Mono<String> result = labelCredentialFactory.mapCredentialAndBindIssuerInToTheCredential(credentialJson, procedureId, testEmail);

        StepVerifier.create(result)
                .expectNext("{\"mocked\": true}")
                .verifyComplete();
    }

    @Test
    void testMapAndBuildLabelCredential() throws JsonProcessingException{
        // Arrange
        String procedureId = "proc-123";
        String email = "test@in2.es";
        String operationMode = "S";
        JsonNode mockNode = mock(JsonNode.class);

        CredentialStatus credentialStatus = mock(CredentialStatus.class);

        LabelCredential.CredentialSubject subject =
                LabelCredential.CredentialSubject.builder()
                        .id("subject-1")
                        .build();

        // Must be ISO_ZONED_DATE_TIME (includes offset/zone), otherwise ZonedDateTime.parse(...) fails
        String validFrom = "2025-01-01T00:00:00Z";
        String validUntil = "2025-01-02T00:00:00Z";

        LabelCredential labelCredential = LabelCredential.builder()
                .credentialSubject(subject)
                .validFrom(validFrom)
                .validUntil(validUntil)
                .build();

        when(objectMapper.convertValue(mockNode, LabelCredential.class))
                .thenReturn(labelCredential);

        when(accessTokenService.getOrganizationIdFromCurrentSession())
                .thenReturn(Mono.just("org-456"));

        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
                .thenReturn("{\"mocked\": true}");

        // Act
        Mono<CredentialProcedureCreationRequest> result =
                labelCredentialFactory.mapAndBuildLabelCredential(
                        procedureId,
                        mockNode,
                        credentialStatus,
                        operationMode,
                        email
                );

        // Assert
        StepVerifier.create(result)
                .assertNext(request -> {
                    assertEquals(procedureId, request.procedureId());
                    assertEquals("subject-1", request.subject());
                    assertEquals(CredentialType.LABEL_CREDENTIAL, request.credentialType());
                    assertEquals(email, request.email());
                    assertEquals(operationMode, request.operationMode());
                    assertEquals("org-456", request.organizationIdentifier());
                    assertNotNull(request.validUntil());
                    assertNotNull(request.credentialDecoded());
                })
                .verifyComplete();

        verify(accessTokenService).getOrganizationIdFromCurrentSession();
        verify(objectMapper).convertValue(mockNode, LabelCredential.class);
        verify(objectMapper).writeValueAsString(any(LabelCredential.class));
    }


    @Test
    void testMapStringToLabelCredential_validV1() throws Exception {
        String credentialJson = "{\"@context\": \"https://trust-framework.dome-marketplace.eu/credentials/labelcredential/v1\"}";
        LabelCredential labelCredential = LabelCredential.builder().id("label-123").build();

        when(objectMapper.readValue(credentialJson, LabelCredential.class))
                .thenReturn(labelCredential);

        LabelCredential result = labelCredentialFactory.mapStringToLabelCredential(credentialJson);

        assertEquals("label-123", result.id());
    }

    @Test
    void testMapIssuer() throws Exception {
        String procedureId = "proc-1";
        String credentialJson = "{\"id\":\"label-1\"}";

        LabelCredential labelCredential = LabelCredential.builder()
                .id("label-1")
                .type(List.of("gx:LabelCredential"))
                .credentialSubject(LabelCredential.CredentialSubject.builder().id("sub-1").build())
                .validFrom(Instant.now().toString())
                .validUntil(Instant.now().plus(1, ChronoUnit.DAYS).toString())
                .build();

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id("issuer-1").build();

        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
                .thenReturn(Mono.just(credentialJson));

        when(objectMapper.readValue(credentialJson, LabelCredential.class))
                .thenReturn(labelCredential);

        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
                .thenReturn("{\"mocked\":true}");

        Mono<String> result = labelCredentialFactory.mapIssuer(procedureId, simpleIssuer);

        StepVerifier.create(result)
                .expectNext("{\"mocked\":true}")
                .verifyComplete();
    }

    @Test
    void testBindIssuer() {
        LabelCredential labelCredential = LabelCredential.builder()
                .id("label-1")
                .type(List.of("gx:LabelCredential"))
                .validFrom(Instant.now().toString())
                .validUntil(Instant.now().plus(1, ChronoUnit.DAYS).toString())
                .credentialSubject(LabelCredential.CredentialSubject.builder().id("sub-1").build())
                .build();

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id("issuer-1").build();

        Mono<LabelCredential> result = labelCredentialFactory.bindIssuer(labelCredential, simpleIssuer);

        StepVerifier.create(result)
                .assertNext(lc -> {
                    assertEquals("label-1", lc.id());
                    assertEquals("issuer-1", lc.issuer().getId());
                })
                .verifyComplete();
    }

    @Test
    void testBuildLabelCredentialJwtPayload() {
        LabelCredential credential = LabelCredential.builder()
                .id("label-1")
                .issuer(SimpleIssuer.builder().id("issuer-123").build())
                .credentialSubject(LabelCredential.CredentialSubject.builder().id("sub-123").build())
                .validFrom(Instant.now().toString())
                .validUntil(Instant.now().plus(1, ChronoUnit.DAYS).toString())
                .build();

        Mono<LabelCredentialJwtPayload> result = labelCredentialFactory.buildLabelCredentialJwtPayload(credential);

        StepVerifier.create(result)
                .assertNext(payload -> {
                    assertEquals("issuer-123", payload.issuer());
                    assertEquals("sub-123", payload.subject());
                    assertNotNull(payload.JwtId());
                    assertNotNull(payload.expirationTime());
                    assertNotNull(payload.issuedAt());
                })
                .verifyComplete();
    }

    @Test
    void testConvertLabelCredentialJwtPayloadInToString() throws Exception {
        LabelCredentialJwtPayload payload = LabelCredentialJwtPayload.builder()
                .JwtId("jwt-id")
                .issuer("issuer-1")
                .subject("sub-1")
                .expirationTime(123456789L)
                .issuedAt(123456700L)
                .notValidBefore(123456700L)
                .build();

        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"jwt\":\"mocked\"}");

        Mono<String> result = labelCredentialFactory.convertLabelCredentialJwtPayloadInToString(payload);

        StepVerifier.create(result)
                .expectNext("{\"jwt\":\"mocked\"}")
                .verifyComplete();
    }

    @Test
    void testMapStringToLabelCredential_throwsInvalidCredentialFormatException() throws Exception {
        String malformedJson = "{invalid_json}";

        // Simulate real failure path: ObjectMapper throws JsonProcessingException
        when(objectMapper.readValue(malformedJson, LabelCredential.class))
                .thenThrow(new JsonProcessingException("boom") {});

        assertThrows(InvalidCredentialFormatException.class, () ->
                labelCredentialFactory.mapStringToLabelCredential(malformedJson));
    }

    @Test
    void convertLabelCredentialInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LabelCredential credential = LabelCredential.builder()
                .id("label-1")
                .type(List.of("gx:LabelCredential"))
                .validFrom(Instant.now().toString())
                .validUntil(Instant.now().plus(1, ChronoUnit.DAYS).toString())
                .credentialSubject(LabelCredential.CredentialSubject.builder().id("sub-1").build())
                .build();

        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
                .thenThrow(new JsonProcessingException("error") {});

        Method m = LabelCredentialFactory.class
                .getDeclaredMethod("convertLabelCredentialInToString", LabelCredential.class);
        m.setAccessible(true);

        Object invokeResult = m.invoke(labelCredentialFactory, credential);

        assertInstanceOf(Mono.class, invokeResult);

        StepVerifier.create((Mono<?>) invokeResult)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(CredentialSerializationException.class, ex);
                    assertEquals("Error serializing LabelCredential to string.", ex.getMessage());
                })
                .verify();
    }

    @Test
    void convertLabelCredentialJwtPayloadInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LabelCredentialJwtPayload payload = mock(LabelCredentialJwtPayload.class);
        when(objectMapper.writeValueAsString(any(LabelCredentialJwtPayload.class)))
                .thenThrow(new JsonProcessingException("error") {});

        Mono<String> result = labelCredentialFactory.convertLabelCredentialJwtPayloadInToString(payload);

        StepVerifier.create(result)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(CredentialSerializationException.class, ex);
                    assertEquals("Error serializing LabelCredential JWT payload to string.", ex.getMessage());
                })
                .verify();
    }
}