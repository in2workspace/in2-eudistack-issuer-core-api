package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.Set;

@Builder
public record CredentialRequest(
        @JsonProperty("format") String format,
        @JsonProperty("credential_definition") CredentialDefinition credentialDefinition,
        @JsonProperty("proofs") Proofs proofs) {

    @Builder
    public record CredentialDefinition(@JsonProperty("type") Set<String> type) {
    }

}
