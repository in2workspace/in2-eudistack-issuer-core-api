package es.in2.issuer.backend.shared.domain.model.dto;

public record GlobalErrorMessage(
        String type,
        String title,
        int status,
        String detail,
        String instance
) {
}
