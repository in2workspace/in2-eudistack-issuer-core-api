package es.in2.issuer.backend.statuslist.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import reactor.core.publisher.Mono;

// Legacy service used to revoke credentials with a PlainListEntry credentialStatus.
// It can be removed once the last credential of this type expires in DOME.
public interface LegacyCredentialStatusRevocationService {

    Mono<Void> revoke(int listId, CredentialStatus credentialStatus);
}
