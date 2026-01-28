package es.in2.issuer.backend.shared.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.*;
import reactor.core.publisher.Mono;

public interface CredentialIssuanceWorkflow {

    Mono<Void> execute(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String bearerToken, String idToken);

    Mono<CredentialResponse> generateVerifiableCredentialResponse(String processId, CredentialRequest credentialRequest, AccessTokenContext token);

    Mono<CredentialResponse> generateVerifiableCredentialDeferredResponse(String processId, DeferredCredentialRequest deferredCredentialRequest, AccessTokenContext accessTokenContext);

    Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, AuthServerNonceRequest authServerNonceRequest);
}
