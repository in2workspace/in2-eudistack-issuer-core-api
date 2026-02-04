package es.in2.issuer.backend.statuslist.domain.service;

import reactor.core.publisher.Flux;

public interface LegacyCredentialStatusQuery {
    Flux<String> getNoncesByListId(String processId, int listId);
}

