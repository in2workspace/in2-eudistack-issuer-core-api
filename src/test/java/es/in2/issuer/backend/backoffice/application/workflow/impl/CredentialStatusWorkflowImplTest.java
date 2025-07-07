package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusAuthorizationService;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
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
    void revokeCredential_ReturnsVoid() {
        String credentialId = "1b59b5f8-a66b-4694-af47-cf38db7a3d73";
        int listId = 1;
        String bearerToken = "bearerToken";

        when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(bearerToken));

        String processId = "processId";
        when(credentialStatusAuthorizationService.authorize(processId, bearerToken, credentialId))
                .thenReturn(Mono.empty());

        CredentialStatus credentialStatus = CredentialStatus.builder().build();
        String decodedCredential = "decodedCredential";
        when(credentialProcedureService.getDecodedCredentialByCredentialId(credentialId))
                .thenReturn(Mono.just(decodedCredential));

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential))
                .thenReturn(LEARCredentialEmployee.builder()
                        .credentialStatus(CredentialStatus.builder().build())
                        .build());

        when(credentialStatusService.revokeCredential(listId, credentialStatus))
                .thenReturn(Mono.empty());

        var result = credentialStatusWorkflow.revokeCredential(
                processId,
                bearerToken,
                credentialId,
                listId);

        StepVerifier
                .create(result)
                .verifyComplete();

        verify(credentialStatusService, times(1)).revokeCredential(listId, credentialStatus);
    }
}