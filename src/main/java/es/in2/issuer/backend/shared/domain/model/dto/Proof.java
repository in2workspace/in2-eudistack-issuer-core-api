package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record Proof(
        @JsonProperty(value = "proof_type", required = true) String proofType,
        @JsonProperty(value = "jwt", required = true) @NotBlank String jwt) {
}
