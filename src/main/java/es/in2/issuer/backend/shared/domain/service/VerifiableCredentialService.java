package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import reactor.core.publisher.Mono;

public interface VerifiableCredentialService {
    Mono<String> generateVc(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String email);
    Mono<CredentialResponse> buildCredentialResponse(String processId, String subjectDid, String authServerNonce, String token, String email, String procedureId);
    Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, String accessToken, String preAuthCode);
    Mono<CredentialResponse> generateDeferredCredentialResponse(CredentialProcedure procedure, String transactionId);
}