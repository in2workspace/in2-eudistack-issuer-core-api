package es.in2.issuer.backend.shared.domain.service;


import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import reactor.core.publisher.Mono;

public interface RemoteSignatureService {
    Mono<SignedData> sign(SignatureRequest signatureRequest, String token);

    Mono<Void> handlePostRecoverError(String procedureId);
}
