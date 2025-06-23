package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

import java.util.List;
import java.util.Map;

@Builder
public record CredentialOffer(
        @JsonProperty(value = "credential_issuer", required = true) @NotBlank String credentialIssuer,
        @JsonProperty(value = "credential_configuration_ids", required = true) List<String> credentialConfigurationIds,
        @JsonProperty(value = "grants", required = true) Map<String, Grants> grants
) {
}
