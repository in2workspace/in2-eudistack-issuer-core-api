package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.CredentialSerializationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialMachineJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_MACHINE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LEARCredentialMachineFactoryTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private AppConfig appConfig;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private IssuerFactory issuerFactory;

    @InjectMocks
    private LEARCredentialMachineFactory learCredentialMachineFactory;

    @Test
    void mapStringToLEARCredentialMachine_shouldDoSuccessfully() throws Exception {
        String credentialV1 = "{\"@context\": \"https://trust-framework.dome-marketplace.eu/credentials/learcredentialmachine/v1\"}";
        LEARCredentialMachine expectedMachine = mock(LEARCredentialMachine.class);

        when(objectMapper.readValue(credentialV1, LEARCredentialMachine.class)).thenReturn(expectedMachine);

        LEARCredentialMachine result = learCredentialMachineFactory.mapStringToLEARCredentialMachine(credentialV1);

        assertEquals(expectedMachine, result);
    }

    @Test
    void testMapAndBuildLEARCredentialMachine() throws JsonProcessingException {
        //Arrange
        String json = "{\"test\": \"test\"}";
        JsonNode jsonNode = objectMapper.readTree(json);
        LEARCredentialMachine.CredentialSubject.Mandate mockMandate = mock(LEARCredentialMachine.CredentialSubject.Mandate.class);
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mockMandatee = mock(LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.class);
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mockMandator = mock(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.class);
        when(appConfig.getIssuerBackendUrl())
                .thenReturn("https://issuer-backend");
        when(objectMapper.convertValue(jsonNode, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(mockMandate);
        when(mockMandate.mandatee()).thenReturn(mockMandatee);
        when(mockMandate.mandator()).thenReturn(mockMandator);
        when(mockMandator.organizationIdentifier()).thenReturn("orgId");

        when(objectMapper.writeValueAsString(any(LEARCredentialMachine.class))).thenReturn(json);

        // Act
        Mono<CredentialProcedureCreationRequest> result = learCredentialMachineFactory.mapAndBuildLEARCredentialMachine(jsonNode, "S", "");

        //Assert
        StepVerifier.create(result)
                .expectNextCount(1)
                .verifyComplete();
    }

    @Test
    void convertLEARCredentialMachineInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LEARCredentialMachine credential = mock(LEARCredentialMachine.class);
        when(objectMapper.writeValueAsString(any(LEARCredentialMachine.class)))
                .thenThrow(new JsonProcessingException("error") {});

        Method m = LEARCredentialMachineFactory.class
                .getDeclaredMethod("convertLEARCredentialMachineInToString", LEARCredentialMachine.class);
        m.setAccessible(true);

        Object invokeResult = m.invoke(learCredentialMachineFactory, credential);

        assertInstanceOf(Mono.class, invokeResult);

        StepVerifier.create((Mono<?>) invokeResult)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(CredentialSerializationException.class, ex);
                    assertEquals("Error serializing LEARCredentialMachine to string.", ex.getMessage());
                })
                .verify();
    }

    @Test
    void convertLEARCredentialMachineJwtPayloadInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LEARCredentialMachineJwtPayload payload = mock(LEARCredentialMachineJwtPayload.class);
        when(objectMapper.writeValueAsString(any(LEARCredentialMachineJwtPayload.class)))
                .thenThrow(new JsonProcessingException("error"){});

        Mono<String> result = learCredentialMachineFactory.convertLEARCredentialMachineJwtPayloadInToString(payload);

        StepVerifier.create(result)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(CredentialSerializationException.class, ex);
                    assertEquals("Error serializing LEARCredentialMachine JWT payload to string.", ex.getMessage());
                })
                .verify();
    }

    @Test
    void mapCredentialAndBindIssuerInToTheCredential_shouldBindDetailedIssuerAndSerialize() throws Exception {
        // Arrange
        String decoded = "{\"@context\":\"https://trust-framework.dome-marketplace.eu/credentials/learcredentialmachine/v1\"}";
        String procedureId = "proc-123";
        DetailedIssuer detailedIssuer = mock(DetailedIssuer.class);

        LEARCredentialMachine baseMachine = mock(LEARCredentialMachine.class);
        when(objectMapper.readValue(decoded, LEARCredentialMachine.class)).thenReturn(baseMachine);
        when(issuerFactory.createDetailedIssuer(procedureId, LEAR_CREDENTIAL_MACHINE, ""))
                .thenReturn(Mono.just(detailedIssuer));

        // capture the final object being serialized to check the issuer is set
        ArgumentCaptor<LEARCredentialMachine> captor = ArgumentCaptor.forClass(LEARCredentialMachine.class);
        when(objectMapper.writeValueAsString(any(LEARCredentialMachine.class))).thenReturn("{\"ok\":true}");

        // Act
        Mono<String> mono = learCredentialMachineFactory.mapCredentialAndBindIssuerInToTheCredential(decoded, procedureId, "");

        // Assert
        StepVerifier.create(mono)
                .expectNext("{\"ok\":true}")
                .verifyComplete();

        verify(objectMapper).writeValueAsString(captor.capture());
        LEARCredentialMachine serialized = captor.getValue();
        assertEquals(detailedIssuer, serialized.issuer());
        verify(issuerFactory).createDetailedIssuer(procedureId, LEAR_CREDENTIAL_MACHINE, "");
    }

    @Test
    void buildLEARCredentialMachineJwtPayload_shouldUseDetailedIssuerIdAndSubject() {
        // Arrange
        DetailedIssuer issuer = mock(DetailedIssuer.class);
        when(issuer.getId()).thenReturn("issuer-id-xyz");

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("mandatee-123")
                        .build();

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandatee(mandatee)
                        .build();

        LEARCredentialMachine.CredentialSubject subject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        LEARCredentialMachine machine = LEARCredentialMachine.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        // Act
        Mono<LEARCredentialMachineJwtPayload> mono = learCredentialMachineFactory.buildLEARCredentialMachineJwtPayload(machine);

        // Assert
        StepVerifier.create(mono)
                .assertNext(payload -> {
                    assertEquals("issuer-id-xyz", payload.issuer());
                    assertEquals("mandatee-123", payload.subject());

                    org.junit.jupiter.api.Assertions.assertTrue(payload.expirationTime() > 0);
                    org.junit.jupiter.api.Assertions.assertTrue(payload.issuedAt() > 0);
                    org.junit.jupiter.api.Assertions.assertTrue(payload.notValidBefore() > 0);
                })
                .verifyComplete();
    }
}