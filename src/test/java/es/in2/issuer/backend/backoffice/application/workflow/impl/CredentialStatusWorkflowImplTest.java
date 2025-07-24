package es.in2.issuer.backend.backoffice.application.workflow.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusAuthorizationService;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialStatusWorkflowImplTest {
    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private CredentialStatusService credentialStatusService;

    @Mock
    private CredentialStatusAuthorizationService credentialStatusAuthorizationService;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @InjectMocks
    private CredentialStatusWorkflowImpl credentialStatusWorkflow;

    @Test
    void getCredentialStatus_ReturnsList() {
        String statusListIndex1 = "1b59b5f8-a66b-4694-af47-cf38db7a3d73";
        String statusListIndex2 = "c046b54b-aa8a-4c8d-af2b-a3d60a61b80b";

        int listId = 1;
        when(credentialStatusService.getCredentialsByListId(listId))
                .thenReturn(Flux.just(statusListIndex1, statusListIndex2));

        var result = credentialStatusWorkflow.getCredentialsByListId("processId", listId);

        StepVerifier
                .create(result)
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex1))
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex2))
                .verifyComplete();
    }

    @Test
    void revokeCredential_ReturnsVoid() throws JsonProcessingException {
        String credentialId = "1b59b5f8-a66b-4694-af47-cf38db7a3d73";
        int listId = 1;
        String bearerToken = "bearerToken";

        String decodedCredential = """
            {
              "@context": ["https://www.w3.org/2018/credentials/v1"],
              "id": "example-id",
              "type": ["VerifiableCredential", "LEARCredentialEmployee"],
              "description": "example-description",
              "credentialSubject": {
                "mandate": {
                  "id": "mandate-id",
                  "life_span": {
                    "end_date_time": "2024-12-31T23:59:59Z",
                    "start_date_time": "2023-01-01T00:00:00Z"
                  },
                  "mandatee": {
                    "id": "mandatee-id",
                    "email": "mandatee@example.com",
                    "firstName": "John",
                    "lastName": "Doe",
                    "mobile_phone": "+123456789",
                    "nationality": "ES"
                  },
                  "mandator": {
                    "commonName": "Company ABC",
                    "country": "Country XYZ",
                    "emailAddress": "mandator@example.com",
                    "organization": "Org ABC",
                    "organizationIdentifier": "org-123",
                    "serialNumber": "1234567890"
                  },
                  "power": [{
                    "id": "power-id",
                    "action": "action",
                    "domain": "domain",
                    "function": "function",
                    "type": "type"
                  }],
                  "signer": null
                }
              },
              "issuer": "did:example:issuer",
              "validFrom": "2023-01-01T00:00:00Z",
              "validUntil": "2023-01-01T00:00:00Z",
              "credentialStatus": {
                "id": "https://issuer.dome-marketplace.eu/credentials/status/1#urn:uuid:8c7a6213-544d-450d-8e3d-b41fa9009198",
                "type": "PlainListEntity",
                "statusPurpose": "revocation",
                "statusListIndex": "urn:uuid:8c7a6213-544d-450d-8e3d-b41fa9009198",
                "statusListCredential": "https://issuer.dome-marketplace.eu/credentials/status/1"
              }
            }
            """;

        ObjectMapper realMapper = new ObjectMapper();

        JsonNode credentialJsonNode = realMapper.readTree(decodedCredential);
        JsonNode credentialStatusNode = credentialJsonNode.get("credentialStatus");

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialStatus(CredentialStatusEnum.VALID);

        when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(bearerToken));

        String processId = "processId";
        when(credentialStatusAuthorizationService.authorize(processId, bearerToken, credentialId))
                .thenReturn(Mono.empty());


        credentialProcedure.setCredentialDecoded(decodedCredential);

        when(credentialProcedureService.getCredentialByCredentialId(credentialId))
                .thenReturn(Mono.just(credentialProcedure));

        when(objectMapper.readTree(decodedCredential)).thenReturn(credentialJsonNode);

        when(credentialStatusService.revokeCredential(eq(listId), any(CredentialStatus.class)))
                .thenReturn(Mono.empty());


        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(credentialProcedure))
                .thenReturn(Mono.empty());

        var result = credentialStatusWorkflow.revokeCredential(
                processId,
                bearerToken,
                credentialId,
                listId);

        StepVerifier
                .create(result)
                .verifyComplete();

        verify(credentialStatusService, times(1)).revokeCredential(eq(listId), any(CredentialStatus.class));

    }
}