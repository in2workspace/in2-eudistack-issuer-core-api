package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface CredentialStatusService {
    Flux<String> getCredentialsByListId(int listId);

    Mono<Void> revokeCredential(int listId, CredentialStatus credentialStatus);
}
