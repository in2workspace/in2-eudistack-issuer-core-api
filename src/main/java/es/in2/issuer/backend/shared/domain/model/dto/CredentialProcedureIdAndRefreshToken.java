package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

@Builder
public record CredentialProcedureIdAndRefreshToken(
        String credentialProcedureId,
        String refreshTokenJti,
        long refreshTokenExpiresAt) {
}
