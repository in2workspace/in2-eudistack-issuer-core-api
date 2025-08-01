package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LEARCredentialMachineFactoryTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CorsProperties corsProperties;

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

        when(corsProperties.defaultAllowedOrigins()).thenReturn(List.of("https://example.com"));
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

}