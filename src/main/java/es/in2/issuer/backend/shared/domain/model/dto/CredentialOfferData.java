package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

@Builder
public record CredentialOfferData(
        CredentialOffer credentialOffer,
        String credentialOwnerEmail,
        String pin
) {
}
