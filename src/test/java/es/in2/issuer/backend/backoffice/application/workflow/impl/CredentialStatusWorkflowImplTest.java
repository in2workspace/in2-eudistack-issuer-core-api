package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialStatusWorkflowImplTest {

    @Mock
    private CredentialStatusService credentialStatusService;

    @InjectMocks
    private CredentialStatusWorkflowImpl credentialStatusWorkflow;

    @Test
    void getCredentialStatus_ReturnsList() {
        String statusListIndex1 = "1b59b5f8-a66b-4694-af47-cf38db7a3d73";
        String statusListIndex2 = "c046b54b-aa8a-4c8d-af2b-a3d60a61b80b";

        when(credentialStatusService.getCredentialsStatus())
                .thenReturn(Flux.just(statusListIndex1, statusListIndex2));

        var result = credentialStatusWorkflow.getCredentialsStatus("processId");

        StepVerifier
                .create(result)
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex1))
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex2))
                .verifyComplete();
    }
}