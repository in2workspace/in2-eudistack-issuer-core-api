package es.in2.issuer.backend.statuslist.domain.service;

import reactor.core.publisher.Flux;

// Legacy service used to handle credentials with a PlainListEntry credentialStatus.
// TODO Remove once the last credential of this type expires in DOME.
public interface LegacyCredentialStatusQuery {
    Flux<String> getNoncesByListId(String processId, int listId);
}

