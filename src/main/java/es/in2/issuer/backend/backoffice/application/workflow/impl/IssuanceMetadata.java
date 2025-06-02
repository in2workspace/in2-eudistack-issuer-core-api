package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import lombok.Builder;

@Builder
public record IssuanceMetadata(
        String preAuthorizedCode,
        String cirId,
        String txCode,
        String email,
        CredentialOffer credentialOffer
) {
}
