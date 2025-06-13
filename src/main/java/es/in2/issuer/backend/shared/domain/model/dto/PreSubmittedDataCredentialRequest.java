package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.validation.constraint.CredentialConfigurationsSupportedConstraint;
import es.in2.issuer.backend.shared.domain.validation.constraint.JwtVcJsonFormatConstraint;
import es.in2.issuer.backend.shared.domain.validation.constraint.SyncOperationModeConstraint;
import lombok.Builder;

@Builder
public record PreSubmittedDataCredentialRequest(
        @JsonProperty(value = "schema", required = true) @CredentialConfigurationsSupportedConstraint String schema,
        @JsonProperty(value = "format", required = true) @JwtVcJsonFormatConstraint String format,
        @JsonProperty(value = "payload", required = true) JsonNode payload,
        @JsonProperty(value = "operation_mode", required = true) @SyncOperationModeConstraint String operationMode,
        @JsonProperty("validity_period") int validityPeriod,
        @JsonProperty("response_uri") String responseUri
) {
}