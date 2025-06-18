package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;

@Builder
public record PreSubmittedCredentialDataRequest(
        @JsonProperty(value = "schema", required = true) String schema,
        @JsonProperty(value = "format", required = true) String format,
        @JsonProperty(value = "payload", required = true) JsonNode payload,
        @JsonProperty("operation_mode") String operationMode,
        @JsonProperty("response_uri") String responseUri,
        @JsonProperty("issuance_notification_uri") String issuanceNotificationUri,
        @JsonProperty("credential_owner_email") String credentialOwnerEmail
) {
}
