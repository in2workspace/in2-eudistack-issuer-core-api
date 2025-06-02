package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import reactor.core.publisher.Mono;

public interface CredentialOfferService {
    Mono<CredentialOffer> buildCustomCredentialOffer(String credentialType, String preAuthorizedCode);

    Mono<String> createCredentialOfferUriResponse(String nonce);
}
