package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeferredCredentialControllerTest {

    @Mock
    private CredentialIssuanceWorkflow credentialIssuanceWorkflow;

    @InjectMocks
    private DeferredCredentialController deferredCredentialController;

    @Test
    void getCredential() {
        String newTransactionId = "newTransactionId";
        DeferredCredentialRequest deferredCredentialRequest = DeferredCredentialRequest.builder()
                .transactionId(newTransactionId)
                .build();
        CredentialResponse credentialResponse = CredentialResponse.builder()
                .credentials(List.of(
                        CredentialResponse.Credential.builder().credential("sampleCredential").build()))
                .build();
        when(credentialIssuanceWorkflow.generateVerifiableCredentialDeferredResponse(anyString(), eq(deferredCredentialRequest), anyString())).thenReturn(Mono.just(credentialResponse));

        Mono<CredentialResponse> result = deferredCredentialController.getCredential("", deferredCredentialRequest);

        StepVerifier.create(result)
                .assertNext(response -> assertEquals(credentialResponse, response))
                .verifyComplete();
    }
}
