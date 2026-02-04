package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.CredentialSerializationException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialEmployeeJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.impl.RemoteSignatureServiceImpl;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.DefaultSignerConfig;
import es.in2.issuer.backend.shared.infrastructure.config.RemoteSignatureConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LEARCredentialEmployeeFactoryTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private RemoteSignatureConfig remoteSignatureConfig;

    @Mock
    private IssuerFactory issuerFactory;

    @InjectMocks
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Mock
    private DefaultSignerConfig defaultSignerConfig;

    @Mock
    private RemoteSignatureServiceImpl remoteSignatureServiceImpl;

    @Mock
    private AppConfig appConfig;


    @Test
    void bindCryptographicCredentialSubjectId_bindsSubjectDidAndSerializes()
            throws Exception {

        // Arrange
        String learCredential =
                "validCredentialStringhttps://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1";
        String subjectDid = "did:example:mandateeId";
        String expectedString = "expectedString";

        var mandatee = LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                .id("old-id")
                .firstName("firstName")
                .lastName("lastName")
                .email("email")
                .employeeId("employeeId")
                .build();

        var mandator = Mandator.builder()
                .organizationIdentifier("orgId")
                .build();

        var mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(mandator)
                .mandatee(mandatee)
                .power(List.of(Power.builder().build()))
                .build();

        var subject = LEARCredentialEmployee.CredentialSubject.builder()
                .id("old-subject-id")
                .mandate(mandate)
                .build();

        var decoded = LEARCredentialEmployee.builder()
                .context(List.of("ctx"))
                .id("cred-id")
                .type(List.of("type"))
                .description("desc")
                .issuer(null)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2026-01-01T00:00:00Z")
                .credentialSubject(subject)
                .credentialStatus(null)
                .build();

        when(objectMapper.readValue(learCredential, LEARCredentialEmployee.class))
                .thenReturn(decoded);

        ArgumentCaptor<LEARCredentialEmployee> captor =
                ArgumentCaptor.forClass(LEARCredentialEmployee.class);

        when(objectMapper.writeValueAsString(captor.capture()))
                .thenAnswer(inv -> {
                    LEARCredentialEmployee updated = captor.getValue();
                    assertEquals(subjectDid, updated.credentialSubject().id());
                    assertEquals("orgId", updated.credentialSubject().mandate().mandator().organizationIdentifier());
                    assertEquals("old-id", updated.credentialSubject().mandate().mandatee().id());
                    return expectedString;
                });

        // Act & Assert
        StepVerifier.create(learCredentialEmployeeFactory.bindCryptographicCredentialSubjectId(learCredential, subjectDid))
                .expectNext(expectedString)
                .verifyComplete();

        verify(objectMapper).readValue(learCredential, LEARCredentialEmployee.class);
        verify(objectMapper).writeValueAsString(any(LEARCredentialEmployee.class));
    }

//    @Test
//    void testMapAndBuildLEARCredentialEmployee() throws JsonProcessingException {
//        //Arrange
//        String json = "{\"test\": \"test\"}";
//        JsonNode jsonNode = objectMapper.readTree(json);
//        LEARCredentialEmployee.CredentialSubject.Mandate mockMandate = mock(LEARCredentialEmployee.CredentialSubject.Mandate.class);
//        Mandator mockMandator = mock(Mandator.class);
//        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mockMandatee = mock(LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.class);
//        Power mockPower = mock(Power.class);
//
//        List<Power> mockPowerList = new ArrayList<>();
//        mockPowerList.add(mockPower);
//
//        when(objectMapper.convertValue(jsonNode, LEARCredentialEmployee.CredentialSubject.Mandate.class))
//                .thenReturn(mockMandate);
//        when(mockMandate.mandator()).thenReturn(mockMandator);
//        when(mockMandate.mandatee()).thenReturn(mockMandatee);
//        when(mockMandate.power()).thenReturn(mockPowerList);
//
//        when(objectMapper.writeValueAsString(any(LEARCredentialEmployee.class))).thenReturn(json);
//        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.just("orgId"));
//
//        when(appConfig.getIssuerBackendUrl()).thenReturn("https://example.org");
//        // Act
//        Mono<CredentialProcedureCreationRequest> result = learCredentialEmployeeFactory.mapAndBuildLEARCredentialEmployee(jsonNode, "S");
//
//        //Assert
//        StepVerifier.create(result)
//                .expectNextCount(1)
//                .verifyComplete();
//    }


    @Test
    void mapCredentialAndBindIssuerInToTheCredential_Server_Success() throws Exception {
        String procedureId = "procedureId";
        String credentialString = "validCredentialStringhttps://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1";
        String expectedString = "expectedString";

        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
        when(objectMapper.readValue(credentialString, LEARCredentialEmployee.class))
                .thenReturn(learCredentialEmployee);

        DetailedIssuer mockIssuer = mock(DetailedIssuer.class);
        when(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .thenReturn(Mono.just(mockIssuer));

        when(objectMapper.writeValueAsString(any(LEARCredentialEmployee.class)))
                .thenReturn(expectedString);

        // Act & Assert
        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId, "")
                )
                .expectNext(expectedString)
                .verifyComplete();

        // Assert
        verify(remoteSignatureServiceImpl, never()).validateCredentials();
    }



    @Test
    void mapCredentialAndBindIssuerInToTheCredential_InvalidCredentials_Error() throws Exception {
        String procedureId = "550e8400-e29b-41d4-a716-446655440000";
        String credentialString = "validCredentialStringhttps://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1";

        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
        when(objectMapper.readValue(credentialString, LEARCredentialEmployee.class))
                .thenReturn(learCredentialEmployee);

        when(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId, "")
                )
                .expectComplete()
                .verify();

        verify(objectMapper, never()).writeValueAsString(any());
    }

    @Test
    void mapCredentialAndBindIssuerInToTheCredential_ValidateCredentials_SuccessOnSecondAttempt() throws Exception {
        String procedureId = "550e8400-e29b-41d4-a716-446655440000";
        String credentialString = "validCredentialStringhttps://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1";
        String expectedString = "expectedString";

        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
        when(objectMapper.readValue(credentialString, LEARCredentialEmployee.class))
                .thenReturn(learCredentialEmployee);

        DetailedIssuer fakeIssuer = mock(DetailedIssuer.class);
        when(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .thenReturn(Mono.just(fakeIssuer));

        when(objectMapper.writeValueAsString(any(LEARCredentialEmployee.class)))
                .thenReturn(expectedString);

        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId, "")
                )
                .expectNext(expectedString)
                .verifyComplete();
    }


    @Test
    void mapCredentialAndBindIssuerInToTheCredential_ValidateCredentials_NonRecoverableError() throws Exception {
        String procedureId = "550e8400-e29b-41d4-a716-446655440000";
        String credentialString = "validCredentialStringhttps://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1";

        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
        when(objectMapper.readValue(credentialString, LEARCredentialEmployee.class))
                .thenReturn(learCredentialEmployee);

        when(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId, "")
                )
                .expectComplete()
                .verify();
    }


    @Test
    void mapCredentialAndBindIssuerInToTheCredential_HandlePostRecoverErrorFails() throws Exception {
        String procedureId = "550e8400-e29b-41d4-a716-446655440000";
        String credentialString = "validCredentialStringhttps://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1";

        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
        when(objectMapper.readValue(credentialString, LEARCredentialEmployee.class))
                .thenReturn(learCredentialEmployee);

        RuntimeException postRecoveryEx = new RuntimeException("Error in post-recovery handling");
        when(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .thenReturn(Mono.error(postRecoveryEx));

        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId, "")
                )
                .expectErrorSatisfies(ex -> {
                    assertSame(postRecoveryEx, ex);
                })
                .verify();
    }

    @Test
    void mapStringToLEARCredentialEmployee_shouldParseV1Successfully() throws Exception {
        String credentialV1 = "{\"@context\": \"https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1\"}";
        LEARCredentialEmployee expectedEmployee = mock(LEARCredentialEmployee.class);

        when(objectMapper.readValue(credentialV1, LEARCredentialEmployee.class)).thenReturn(expectedEmployee);

        LEARCredentialEmployee result = learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(credentialV1);

        assertEquals(expectedEmployee, result);
    }
    @Test
    void mapStringToLEARCredentialEmployee_shouldCleanAndParseV2Successfully() throws Exception {
        String credentialV2 = """
        {
          "@context": "https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2",
          "credentialSubject": {
            "mandate": {
              "power": [
                {
                  "tmf_function": "value1",
                  "tmf_type": "value2",
                  "tmf_domain": "value3",
                  "tmf_action": "value4",
                  "other_field": "keep"
                }
              ]
            }
          }
        }
        """;

        JsonNode modifiedNode = new ObjectMapper().readTree("""
        {
          "@context": "https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2",
          "credentialSubject": {
            "mandate": {
              "power": [
                {
                  "other_field": "keep"
                }
              ]
            }
          }
        }
        """);

        LEARCredentialEmployee expectedEmployee = mock(LEARCredentialEmployee.class);

        when(objectMapper.readTree(credentialV2)).thenReturn(modifiedNode);
        when(objectMapper.readValue(modifiedNode.toString(), LEARCredentialEmployee.class)).thenReturn(expectedEmployee);

        LEARCredentialEmployee result = learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(credentialV2);

        assertEquals(expectedEmployee, result);
    }

    @Test
    void mapStringToLEARCredentialEmployee_shouldThrowExceptionForInvalidFormat() {
        String invalidCredential = "{\"@context\": \"https://invalid-url.org/credential/unknown\"}";

        InvalidCredentialFormatException exception = assertThrows(
                InvalidCredentialFormatException.class,
                () -> learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(invalidCredential)
        );

        assertEquals("Invalid credential format", exception.getMessage());
    }

    @Test
    void convertLEARCredentialEmployeeInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LEARCredentialEmployee credential = mock(LEARCredentialEmployee.class);
        when(objectMapper.writeValueAsString(any(LEARCredentialEmployee.class)))
                .thenThrow(new JsonProcessingException("error") {});

        Method m = LEARCredentialEmployeeFactory.class
                .getDeclaredMethod("convertLEARCredentialEmployeeInToString", LEARCredentialEmployee.class);
        m.setAccessible(true);

        Object invokeResult = m.invoke(learCredentialEmployeeFactory, credential);

        assertInstanceOf(Mono.class, invokeResult);

        StepVerifier.create((Mono<?>) invokeResult)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(CredentialSerializationException.class, ex);
                    assertEquals("Error serializing LEARCredentialEmployee to string.", ex.getMessage());
                })
                .verify();
    }

    @Test
    void convertLEARCredentialEmployeeJwtPayloadInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LEARCredentialEmployeeJwtPayload payload = mock(LEARCredentialEmployeeJwtPayload.class);
        when(objectMapper.writeValueAsString(any(LEARCredentialEmployeeJwtPayload.class)))
                .thenThrow(new JsonProcessingException("error"){});

        Mono<String> result = learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(payload);

        StepVerifier.create(result)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(CredentialSerializationException.class, ex);
                    assertEquals("Error serializing LEARCredentialEmployee JWT payload to string.", ex.getMessage());
                })
                .verify();
    }

    @Test
    void buildLEARCredentialEmployeeJwtPayload_success_setsSubjectIssuerTimesAndCnfKid() {
        // Arrange
        DetailedIssuer issuer = mock(DetailedIssuer.class);
        when(issuer.getId()).thenReturn("issuer-id-123");

        LEARCredentialEmployee.CredentialSubject subject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .id("did:key:zDnaeiLt1XYBTBZk123#key-1")
                        .mandate(mock(LEARCredentialEmployee.CredentialSubject.Mandate.class))
                        .build();

        LEARCredentialEmployee vc = LEARCredentialEmployee.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        // Act
        Mono<LEARCredentialEmployeeJwtPayload> mono =
                learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(vc);

        // Assert
        StepVerifier.create(mono)
                .assertNext(payload -> {
                    assertNotNull(payload.JwtId());
                    assertEquals(vc, payload.learCredentialEmployee());
                    assertEquals("issuer-id-123", payload.issuer());
                    assertEquals("did:key:zDnaeiLt1XYBTBZk123#key-1", payload.subject());

                    assertNotNull(payload.cnf());
                    assertInstanceOf(java.util.Map.class, payload.cnf());

                    @SuppressWarnings("unchecked")
                    java.util.Map<String, Object> cnf = (java.util.Map<String, Object>) payload.cnf();

                    assertEquals("did:key:zDnaeiLt1XYBTBZk123#key-1", cnf.get("kid"));

                    assertTrue(payload.issuedAt() > 0);
                    assertTrue(payload.notValidBefore() > 0);
                    assertTrue(payload.expirationTime() > 0);
                    assertTrue(payload.expirationTime() >= payload.issuedAt());
                })
                .verifyComplete();
    }


    @Test
    void buildLEARCredentialEmployeeJwtPayload_whenCredentialSubjectIdNull_emitsIllegalStateException() {
        DetailedIssuer issuer = mock(DetailedIssuer.class);

        LEARCredentialEmployee.CredentialSubject subject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .id(null)
                        .mandate(mock(LEARCredentialEmployee.CredentialSubject.Mandate.class))
                        .build();

        LEARCredentialEmployee vc = LEARCredentialEmployee.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        StepVerifier.create(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(vc))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(IllegalStateException.class, ex);
                    assertEquals("Missing credentialSubject.id (cryptographic binding DID)", ex.getMessage());
                })
                .verify();
    }

    @Test
    void buildLEARCredentialEmployeeJwtPayload_whenCredentialSubjectIdBlank_emitsIllegalStateException() {
        DetailedIssuer issuer = mock(DetailedIssuer.class);

        LEARCredentialEmployee.CredentialSubject subject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .id("   ")
                        .mandate(mock(LEARCredentialEmployee.CredentialSubject.Mandate.class))
                        .build();

        LEARCredentialEmployee vc = LEARCredentialEmployee.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        StepVerifier.create(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(vc))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(IllegalStateException.class, ex);
                    assertEquals("Missing credentialSubject.id (cryptographic binding DID)", ex.getMessage());
                })
                .verify();
    }

    @Test
    void buildLEARCredentialEmployeeJwtPayload_setsStandardClaims() {
        DetailedIssuer issuer = mock(DetailedIssuer.class);
        when(issuer.getId()).thenReturn("issuer-id-123");

        var mandate = mock(LEARCredentialEmployee.CredentialSubject.Mandate.class);

        var subject = LEARCredentialEmployee.CredentialSubject.builder()
                .id("did:key:zDnaeiLt1XYBTBZk123#key-1")
                .mandate(mandate)
                .build();

        var vc = LEARCredentialEmployee.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        StepVerifier.create(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(vc))
                .assertNext(payload -> {
                    assertAll(
                            () -> assertNotNull(payload.JwtId()),
                            () -> assertEquals("issuer-id-123", payload.issuer()),
                            () -> assertEquals("did:key:zDnaeiLt1XYBTBZk123#key-1", payload.subject())
                    );
                })
                .verifyComplete();
    }


    @Test
    void buildLEARCredentialEmployeeJwtPayload_setsCnfKidFromSubjectId() {
        DetailedIssuer issuer = mock(DetailedIssuer.class);
        when(issuer.getId()).thenReturn("issuer-id-123");

        var mandate = mock(LEARCredentialEmployee.CredentialSubject.Mandate.class);

        var subject = LEARCredentialEmployee.CredentialSubject.builder()
                .id("did:key:zDnaeiLt1XYBTBZk123#key-1")
                .mandate(mandate)
                .build();

        var vc = LEARCredentialEmployee.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        StepVerifier.create(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(vc))
                .assertNext(payload -> {
                    assertInstanceOf(Map.class, payload.cnf());
                    var cnf = (Map<String, Object>) payload.cnf();

                    assertEquals("did:key:zDnaeiLt1XYBTBZk123#key-1", cnf.get("kid"));
                })
                .verifyComplete();
    }


    @Test
    void buildLEARCredentialEmployeeJwtPayload_setsTimestampsConsistently() {
        DetailedIssuer issuer = mock(DetailedIssuer.class);
        when(issuer.getId()).thenReturn("issuer-id-123");

        var mandate = mock(LEARCredentialEmployee.CredentialSubject.Mandate.class);

        var subject = LEARCredentialEmployee.CredentialSubject.builder()
                .id("did:key:zDnaeiLt1XYBTBZk123#key-1")
                .mandate(mandate)
                .build();

        var vc = LEARCredentialEmployee.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        StepVerifier.create(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(vc))
                .assertNext(payload -> {
                    assertAll(
                            () -> assertTrue(payload.issuedAt() > 0),
                            () -> assertTrue(payload.notValidBefore() > 0),
                            () -> assertTrue(payload.expirationTime() > 0),
                            () -> assertTrue(payload.expirationTime() >= payload.issuedAt())
                    );
                })
                .verifyComplete();
    }

    @Test
    void buildLEARCredentialEmployeeJwtPayload_whenSubjectDidMissing_emitsIllegalStateException() {
        DetailedIssuer issuer = mock(DetailedIssuer.class);

        var subject = LEARCredentialEmployee.CredentialSubject.builder()
                .id("   ") // blank
                .mandate(mock(LEARCredentialEmployee.CredentialSubject.Mandate.class))
                .build();

        var vc = LEARCredentialEmployee.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        StepVerifier.create(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(vc))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(IllegalStateException.class, ex);
                    assertEquals("Missing credentialSubject.id (cryptographic binding DID)", ex.getMessage());
                })

                .verify();
    }

    @Test
    void buildLEARCredentialEmployeeJwtPayload_whenDatesInvalid_emitsDateTimeParseException() {
        DetailedIssuer issuer = mock(DetailedIssuer.class);

        var subject = LEARCredentialEmployee.CredentialSubject.builder()
                .id("did:key:zDnaeiLt1XYBTBZk123#key-1")
                .mandate(mock(LEARCredentialEmployee.CredentialSubject.Mandate.class))
                .build();

        var vc = LEARCredentialEmployee.builder()
                .issuer(issuer)
                .validFrom("not-a-date")
                .validUntil("also-bad")
                .credentialSubject(subject)
                .build();

        StepVerifier.create(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(vc))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(DateTimeParseException.class, ex);
                    assertTrue(ex.getMessage().contains("also-bad"));
                })
                .verify();
    }


}