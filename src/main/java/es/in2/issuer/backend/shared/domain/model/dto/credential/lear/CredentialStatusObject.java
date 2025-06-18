package es.in2.issuer.backend.shared.domain.model.dto.credential.lear;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialStatusObject(
        @JsonProperty("id") String id,
        @JsonProperty("type") String type,
        @JsonProperty("statusPurpose") String statusPurpose,
        @JsonProperty("statusListIndex") String statusListIndex,
        @JsonProperty("statusListCredential") String statusListCredential
) {
}
