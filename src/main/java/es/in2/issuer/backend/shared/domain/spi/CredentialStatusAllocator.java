package es.in2.issuer.backend.shared.domain.spi;

import reactor.core.publisher.Mono;


import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;

public interface CredentialStatusAllocator {

    Mono<CredentialStatus> allocate(
            String issuerId,
            String credentialId,
            String token
    );
}

