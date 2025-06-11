package es.in2.issuer.backend.shared.domain.model.dto.credential;

import lombok.Builder;

@Builder
public record CredentialStatusObject (String id, String type, String statusPurpose, String statusListIndex, String statusListCredential) {
}
