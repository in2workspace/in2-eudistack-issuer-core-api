package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record NotificationErrorResponse(
        String error,
        @JsonProperty("error_description") String errorDescription
) {}

