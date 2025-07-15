package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialEmployeeJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.impl.RemoteSignatureServiceImpl;
import es.in2.issuer.backend.shared.domain.util.Constants;
import es.in2.issuer.backend.shared.infrastructure.config.DefaultSignerConfig;
import es.in2.issuer.backend.shared.infrastructure.config.RemoteSignatureConfig;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.List;

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
    private CorsProperties corsProperties;

    
    @Test
    void testMapCredentialAndBindMandateeIdInToTheCredential() throws JsonProcessingException, InvalidCredentialFormatException {
        //Arrange
        String learCredential = "validCredentialStringhttps://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1";
        String mandateeId = "mandateeId";
        String expectedString = "expectedString";
        LEARCredentialEmployeeJwtPayload learCredentialEmployeeJwtPayload = mock(LEARCredentialEmployeeJwtPayload.class);
        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
        LEARCredentialEmployee.CredentialSubject credentialSubject = mock(LEARCredentialEmployee.CredentialSubject.class);
        LEARCredentialEmployee.CredentialSubject.Mandate mandate = mock(LEARCredentialEmployee.CredentialSubject.Mandate.class);
        Mandator mandator = mock(Mandator.class);
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee = mock(LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.class);

        when(objectMapper.readValue(learCredential, LEARCredentialEmployee.class)).thenReturn(learCredentialEmployee);
        when(learCredentialEmployeeJwtPayload.learCredentialEmployee()).thenReturn(learCredentialEmployee);
        when(learCredentialEmployeeJwtPayload.learCredentialEmployee().credentialSubject()).thenReturn(credentialSubject);
        when(credentialSubject.mandate()).thenReturn(mandate);
        when(mandate.id()).thenReturn("mandateeId");
        when(mandate.mandator()).thenReturn(mandator);
        when(mandate.mandatee()).thenReturn(mandatee);
        when(mandatee.email()).thenReturn("email");
        when(mandatee.firstName()).thenReturn("firstName");
        when(mandatee.lastName()).thenReturn("lastName");
        when(mandatee.nationality()).thenReturn("nationality");
        when(mandate.power()).thenReturn(List.of(Power.builder().build()));
        when(objectMapper.writeValueAsString(any(LEARCredentialEmployee.class))).thenReturn(expectedString);

        //Act & Assert
        StepVerifier.create(learCredentialEmployeeFactory.mapCredentialAndBindMandateeIdInToTheCredential(learCredential, mandateeId))
                .expectNext(expectedString)
                .verifyComplete();
    }

    @Test
    void testMapAndBuildLEARCredentialEmployee() throws JsonProcessingException {
        //Arrange
        String json = "{\"test\": \"test\"}";
        JsonNode jsonNode = objectMapper.readTree(json);
        LEARCredentialEmployee.CredentialSubject.Mandate mockMandate = mock(LEARCredentialEmployee.CredentialSubject.Mandate.class);
        Mandator mockMandator = mock(Mandator.class);
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mockMandatee = mock(LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.class);
        Power mockPower = mock(Power.class);

        List<Power> mockPowerList = new ArrayList<>();
        mockPowerList.add(mockPower);

        when(objectMapper.convertValue(jsonNode, LEARCredentialEmployee.CredentialSubject.Mandate.class))
                .thenReturn(mockMandate);
        when(mockMandate.mandator()).thenReturn(mockMandator);
        when(mockMandate.mandatee()).thenReturn(mockMandatee);
        when(mockMandate.power()).thenReturn(mockPowerList);

        when(objectMapper.writeValueAsString(any(LEARCredentialEmployee.class))).thenReturn(json);
        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.just("orgId"));

        when(corsProperties.defaultAllowedOrigins()).thenReturn(List.of("https://example.org"));

        // Act
        Mono<CredentialProcedureCreationRequest> result = learCredentialEmployeeFactory.mapAndBuildLEARCredentialEmployee(jsonNode, "S");

        //Assert
        StepVerifier.create(result)
                .expectNextCount(1)
                .verifyComplete();
    }


    @Test
    void mapCredentialAndBindIssuerInToTheCredential_Server_Success() throws Exception {
        String procedureId = "procedureId";
        String credentialString = "validCredentialStringhttps://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1";
        String expectedString = "expectedString";

        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
        when(objectMapper.readValue(credentialString, LEARCredentialEmployee.class))
                .thenReturn(learCredentialEmployee);

        DetailedIssuer mockIssuer = mock(DetailedIssuer.class);
        when(issuerFactory.createIssuer(procedureId, Constants.LEAR_CREDENTIAL_EMPLOYEE))
                .thenReturn(Mono.just(mockIssuer));

        when(objectMapper.writeValueAsString(any(LEARCredentialEmployee.class)))
                .thenReturn(expectedString);

        // Act & Assert
        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId)
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

        when(issuerFactory.createIssuer(procedureId, Constants.LEAR_CREDENTIAL_EMPLOYEE))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId)
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
        when(issuerFactory.createIssuer(procedureId, Constants.LEAR_CREDENTIAL_EMPLOYEE))
                .thenReturn(Mono.just(fakeIssuer));

        when(objectMapper.writeValueAsString(any(LEARCredentialEmployee.class)))
                .thenReturn(expectedString);

        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId)
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

        when(issuerFactory.createIssuer(procedureId, Constants.LEAR_CREDENTIAL_EMPLOYEE))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId)
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
        when(issuerFactory.createIssuer(procedureId, Constants.LEAR_CREDENTIAL_EMPLOYEE))
                .thenReturn(Mono.error(postRecoveryEx));

        StepVerifier.create(
                        learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(credentialString, procedureId)
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
}