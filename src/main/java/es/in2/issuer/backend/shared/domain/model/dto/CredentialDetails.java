package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;

import java.util.UUID;
@Builder
public record CredentialDetails(
        @JsonProperty("procedure_id") UUID procedureId,
        @JsonProperty("lifeCycleStatus") String lifeCycleStatus,
        @JsonProperty("operation_mode") String operationMode,
        @JsonProperty("signature_mode") String signatureMode,
        @JsonProperty("credential") JsonNode credential
        ) {
}
