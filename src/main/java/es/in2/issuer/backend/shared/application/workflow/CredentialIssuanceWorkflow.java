package es.in2.issuer.backend.shared.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.*;
import reactor.core.publisher.Mono;

public interface CredentialIssuanceWorkflow {

    Mono<Void> execute(String processId, PreSubmittedCredentialRequest preSubmittedCredentialRequest, String bearerToken, String idToken);

    // Refactor
    Mono<VerifiableCredentialResponse> generateVerifiableCredentialResponse(String processId, CredentialRequest credentialRequest, String token);

    Mono<BatchCredentialResponse> generateVerifiableCredentialBatchResponse(String username, BatchCredentialRequest batchCredentialRequest, String token);

    Mono<VerifiableCredentialResponse> generateVerifiableCredentialDeferredResponse(String processId, DeferredCredentialRequest deferredCredentialRequest);

    Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, AuthServerNonceRequest authServerNonceRequest);
}
