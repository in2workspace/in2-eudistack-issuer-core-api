package es.in2.issuer.backend.credentialStatus.domain.service;

import reactor.core.publisher.Flux;

import java.util.UUID;

public interface LegacyCredentialStatusQuery {
    Flux<String> getNoncesByListId(String processId, int listId);
}

