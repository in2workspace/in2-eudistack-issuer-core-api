package es.in2.issuer.backend.shared.domain.service;

import reactor.core.publisher.Mono;

import java.util.Set;

public interface ProofValidationService {
    Mono<Boolean> isProofValid(String jwtProof, String token, Set<String> allowedAlgs);
}
