package es.in2.issuer.backend.backoffice.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusAuthorizationService;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialStatusWorkflowImplTest {

    @Mock private ObjectMapper objectMapper;
    @Mock private AccessTokenService accessTokenService;
    @Mock private CredentialStatusService credentialStatusService;
    @Mock private CredentialStatusAuthorizationService credentialStatusAuthorizationService;
    @Mock private CredentialProcedureService credentialProcedureService;
    @Mock private EmailService emailService;
    @Mock private BackofficePdpService backofficePdpService;

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

        StepVerifier.create(result)
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex1))
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex2))
                .verifyComplete();
    }

    @Test
    void revokeCredential_ReturnsVoid() throws Exception {
        String credentialProcedureId = "1b59b5f8-a66b-4694-af47-cf38db7a3d73";
        int listId = 1;
        String bearerToken = "bearerToken";
        String cleanToken = "cleanToken";

        String decodedCredential = """
        {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          "id": "example-id",
          "type": ["VerifiableCredential", "LEARCredentialEmployee"],
          "credentialStatus": {
            "id": "https://issuer/credentials/status/1#urn:uuid:8c7a6213",
            "type": "PlainListEntity",
            "statusPurpose": "revocation",
            "statusListIndex": "urn:uuid:8c7a6213",
            "statusListCredential": "https://issuer/credentials/status/1"
          }
        }
        """;

        ObjectMapper realMapper = new ObjectMapper();
        JsonNode root = realMapper.readTree(decodedCredential);

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        credentialProcedure.setCredentialDecoded(decodedCredential);
        credentialProcedure.setProcedureId(UUID.randomUUID());

        when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));

        when(backofficePdpService.validateRevokeCredential("processId", cleanToken, credentialProcedureId))
                .thenReturn(Mono.empty());

        when(credentialProcedureService.getCredentialProcedureById(credentialProcedureId))
                .thenReturn(Mono.just(credentialProcedure));

        when(objectMapper.readTree(decodedCredential)).thenReturn(root);

        when(credentialStatusService.revokeCredential(eq(listId), any(CredentialStatus.class)))
                .thenReturn(Mono.empty());

        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(credentialProcedure))
                .thenReturn(Mono.empty());

        when(emailService.notifyIfCredentialStatusChanges(any(), any()))
                .thenReturn(Mono.empty());

        Mono<Void> result = credentialStatusWorkflow.revokeCredential("processId", bearerToken, credentialProcedureId, listId);

        StepVerifier.create(result).verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(backofficePdpService).validateRevokeCredential("processId", cleanToken, credentialProcedureId);
        verify(credentialStatusService, times(1))
                .revokeCredential(eq(listId), any(CredentialStatus.class));
        verify(emailService, times(1))
                .notifyIfCredentialStatusChanges(credentialProcedure, "REVOKED");
    }

    @Test
    void revokeCredential_SendsEmailWhenRevoked() throws Exception {
        String processId = "processId";
        String bearerToken = "bearerToken";
        String cleanToken = "cleanToken";
        String credentialProcedureId = "cred-123";
        int listId = 7;

        CredentialProcedure cp = new CredentialProcedure();
        cp.setCredentialDecoded("""
            {"credentialStatus":{
              "id":"x","type":"PlainListEntity","statusPurpose":"revocation",
              "statusListIndex":"idx","statusListCredential":"url"}}
            """);
        cp.setCredentialStatus(CredentialStatusEnum.VALID);
        cp.setProcedureId(UUID.randomUUID());
        cp.setCredentialType("LEARCredentialEmployee");

        ObjectMapper real = new ObjectMapper();
        JsonNode root = real.readTree(cp.getCredentialDecoded());

        when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));

        when(backofficePdpService.validateRevokeCredential(processId, cleanToken, credentialProcedureId))
                .thenReturn(Mono.empty());

        when(credentialProcedureService.getCredentialProcedureById(credentialProcedureId))
                .thenReturn(Mono.just(cp));

        when(objectMapper.readTree(cp.getCredentialDecoded()))
                .thenReturn(root);

        when(credentialStatusService.revokeCredential(eq(listId), any(CredentialStatus.class)))
                .thenReturn(Mono.empty());

        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> {
                    CredentialProcedure arg = invocation.getArgument(0);
                    arg.setCredentialStatus(CredentialStatusEnum.REVOKED);
                    return Mono.empty();
                });

        when(emailService.notifyIfCredentialStatusChanges(any(), anyString()))
                .thenReturn(Mono.empty());

        Mono<Void> result = credentialStatusWorkflow.revokeCredential(processId, bearerToken, credentialProcedureId, listId);

        StepVerifier.create(result).verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(backofficePdpService).validateRevokeCredential(processId, cleanToken, credentialProcedureId);
        verify(credentialStatusService).revokeCredential(eq(listId), any(CredentialStatus.class));
        verify(emailService).notifyIfCredentialStatusChanges(cp, "REVOKED");
    }
}
