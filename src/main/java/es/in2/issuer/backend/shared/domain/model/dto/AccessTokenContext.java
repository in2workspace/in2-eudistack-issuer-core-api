package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

@Builder
public record AccessTokenContext(
        String rawToken,
        String jti,
        String procedureId,
        String responseUri
) {}
