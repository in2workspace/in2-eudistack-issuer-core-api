package es.in2.issuer.backend.backoffice.domain.service;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface CredentialStatusService {
    Flux<String> getCredentialsStatusByListId(int listId);

    Mono<Void> revokeCredential(String credentialId, int listId);
}
