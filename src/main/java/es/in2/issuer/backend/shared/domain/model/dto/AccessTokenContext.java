package es.in2.issuer.backend.shared.domain.model.dto;

public record AccessTokenContext(
        String rawToken,
        String jti,
        String procedureId
) {}
