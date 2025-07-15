package es.in2.issuer.backend.backoffice.domain.service;

import reactor.core.publisher.Mono;

public interface CredentialStatusAuthorizationService {
    Mono<Void> authorize(String processId, String token, String credentialId);
}
