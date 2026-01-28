package es.in2.issuer.backend.credentialStatus.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import reactor.core.publisher.Mono;

public interface LegacyCredentialStatusRevocationService {

    Mono<Void> revoke(int listId, CredentialStatus credentialStatus);
}
