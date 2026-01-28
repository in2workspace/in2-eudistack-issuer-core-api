package es.in2.issuer.backend.shared.domain.service;


import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import reactor.core.publisher.Mono;

public interface RemoteSignatureService {
    Mono<SignedData> signIssuedCredential(SignatureRequest signatureRequest, String token, String procedureId, String email);
    Mono<SignedData> signSystemCredential(SignatureRequest signatureRequest, String token);
}
