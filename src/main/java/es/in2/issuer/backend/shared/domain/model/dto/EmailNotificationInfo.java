package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

@Builder
public record EmailNotificationInfo(
        String email,
        String user,
        String organization
) {
}