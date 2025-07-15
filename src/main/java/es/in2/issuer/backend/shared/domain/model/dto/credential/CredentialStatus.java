package es.in2.issuer.backend.shared.domain.model.dto.credential;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialStatus(
        @JsonProperty("id") String id,
        @JsonProperty("type") String type,
        @JsonProperty("statusPurpose") String statusPurpose,
        @JsonProperty("statusListIndex") String statusListIndex,
        @JsonProperty("statusListCredential") String statusListCredential
) {
}
