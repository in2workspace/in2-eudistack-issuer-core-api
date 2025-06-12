package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedDataCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.VerifiableCredentialResponse;
import reactor.core.publisher.Mono;

public interface VerifiableCredentialService {
    Mono<String> generateVc(String processId, String vcType, PreSubmittedDataCredentialRequest preSubmittedCredentialRequest, String token);
    Mono<String> generateVerifiableCertification(String processId, PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest, String idToken);
    Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, String accessToken, String preAuthCode);
    Mono<VerifiableCredentialResponse> generateDeferredCredentialResponse(String processId, DeferredCredentialRequest deferredCredentialRequest);

    Mono<VerifiableCredentialResponse> buildCredentialResponseBasedOnOperationMode(String operationMode, String procedureId, String transactionId, String authServerNonce, String token);
}
