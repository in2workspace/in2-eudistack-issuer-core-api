package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import reactor.core.publisher.Mono;

public interface VerifiableCredentialService {
    Mono<String> generateVc(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String email);
    Mono<CredentialResponse> buildCredentialResponse(String processId, String subjectDid, String authServerNonce, String token, String email);
    Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, String accessToken, String preAuthCode);
    Mono<CredentialResponse> signDeferredCredential(String processId,
                                                    String procedureId,
                                                    String credentialType,
                                                    String boundCredential,
                                                    String format,
                                                    String authServerNonce,
                                                    String transactionId,
                                                    String token);
}