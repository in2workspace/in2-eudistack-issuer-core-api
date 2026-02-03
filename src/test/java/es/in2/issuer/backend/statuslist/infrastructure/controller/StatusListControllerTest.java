package es.in2.issuer.backend.statuslist.infrastructure.controller;

import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.dto.RevokeCredentialRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class StatusListControllerUnitTest {

    private StatusListWorkflow statusListWorkflow;
    private RevocationWorkflow revocationWorkflow;
    private StatusListController controller;

    @BeforeEach
    void setUp() {
        statusListWorkflow = mock(StatusListWorkflow.class);
        revocationWorkflow = mock(RevocationWorkflow.class);
        controller = new StatusListController(statusListWorkflow, revocationWorkflow);
    }

    @Test
    void getStatusList_whenOk_returnsResponseEntityWithVcJwt() {
        long listId = 123L;
        String jwt = "header.payload.signature";

        when(statusListWorkflow.getSignedStatusListCredential(listId)).thenReturn(Mono.just(jwt));

        Mono<ResponseEntity<String>> result = controller.getStatusList(listId);

        StepVerifier.create(result)
                .assertNext(res -> {
                    assertThat(res.getStatusCode().value()).isEqualTo(200);
                    assertThat(res.getHeaders().getContentType()).isEqualTo(MediaType.parseMediaType("application/vc+jwt"));
                    assertThat(res.getBody()).isEqualTo(jwt);
                })
                .verifyComplete();

        verify(statusListWorkflow).getSignedStatusListCredential(listId);
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void getStatusList_whenWorkflowFails_propagatesError() {
        long listId = 123L;

        when(statusListWorkflow.getSignedStatusListCredential(listId))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(controller.getStatusList(listId))
                .expectError(RuntimeException.class)
                .verify();

        verify(statusListWorkflow).getSignedStatusListCredential(listId);
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void revokeCredential_whenOk_completesAndInvokesWorkflow() {
        String bearerToken = "Bearer test-token";
        String procedureId = UUID.randomUUID().toString();
        int listId = 99;

        RevokeCredentialRequest request = new RevokeCredentialRequest(procedureId, listId);

        when(revocationWorkflow.revoke(anyString(), eq(bearerToken), eq(procedureId), eq(listId)))
                .thenReturn(Mono.empty());

        StepVerifier.create(controller.revokeCredential(bearerToken, request))
                .verifyComplete();

        verify(revocationWorkflow).revoke(anyString(), eq(bearerToken), eq(procedureId), eq(listId));
        verifyNoInteractions(statusListWorkflow);
    }

    @Test
    void revokeCredential_whenWorkflowFails_propagatesError() {
        String bearerToken = "Bearer test-token";
        String procedureId = UUID.randomUUID().toString();
        int listId = 99;

        RevokeCredentialRequest request = new RevokeCredentialRequest(procedureId, listId);

        when(revocationWorkflow.revoke(anyString(), eq(bearerToken), eq(procedureId), eq(listId)))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(controller.revokeCredential(bearerToken, request))
                .expectError(RuntimeException.class)
                .verify();

        verify(revocationWorkflow).revoke(anyString(), eq(bearerToken), eq(procedureId), eq(listId));
        verifyNoInteractions(statusListWorkflow);
    }
}
