package es.in2.issuer.backend.statuslist.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record LegacyCredentialStatusResponse(
        @JsonProperty("nonce") String credentialNonce) {
}
