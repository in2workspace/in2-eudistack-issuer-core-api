package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

import java.util.List;

@Builder
public record Proofs(
        @Schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiw....WZwmhmn9OQp6YxX0a2L", description = "Contains the access token obtained with the pre-authorized code") @JsonProperty("jwt") List<String> jwt) {
}
