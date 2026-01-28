package es.in2.issuer.backend.shared.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.*;
import reactor.core.publisher.Mono;

public interface CredentialIssuanceWorkflow {

    Mono<Void> execute(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String bearerToken, String idToken);

    // Refactor
    Mono<CredentialResponse> generateVerifiableCredentialResponse(String processId, CredentialRequest credentialRequest, String token);

    Mono<DeferredCredentialResponse> generateVerifiableCredentialDeferredResponse(String processId, DeferredCredentialRequest deferredCredentialRequest);

    Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, AuthServerNonceRequest authServerNonceRequest);
}
