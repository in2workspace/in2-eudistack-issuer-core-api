package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

import java.util.List;
import java.util.Map;

@Builder
public record CredentialOffer(
        @JsonProperty("credential_issuer") @NotBlank String credentialIssuer,
        @JsonProperty("credential_configuration_ids") List<String> credentialConfigurationIds,
        @JsonProperty("grants") Map<String, Grants> grants
) {
}
