package es.in2.issuer.backend.credentialStatus.domain.service;

import reactor.core.publisher.Flux;

public interface LegacyCredentialStatusQuery {
    Flux<String> getNoncesByListId(int listId);
}

