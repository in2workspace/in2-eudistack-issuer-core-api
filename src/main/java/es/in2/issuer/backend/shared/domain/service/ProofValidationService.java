package es.in2.issuer.backend.shared.domain.service;

import reactor.core.publisher.Mono;

public interface ProofValidationService {
    Mono<Void> ensureIsProofValid(String jwtProof, String token);
}
