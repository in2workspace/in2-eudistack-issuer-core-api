package es.in2.issuer.backend.credentialstatus.domain.model.entities.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialStatusResponse(
        @JsonProperty("nonce") String credentialNonce) {
}
