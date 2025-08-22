package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.CredentialSerializationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialMachineJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LEARCredentialMachineFactoryTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private AppConfig appConfig;

    @Mock
    private AccessTokenService accessTokenService;

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

        when(appConfig.getIssuerBackendUrl())
                .thenReturn("https://issuer-backend");
        when(objectMapper.convertValue(jsonNode, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(mockMandate);
        when(mockMandate.mandatee()).thenReturn(mockMandatee);

        when(objectMapper.writeValueAsString(any(LEARCredentialMachine.class))).thenReturn(json);
        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.just("orgId"));

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
}