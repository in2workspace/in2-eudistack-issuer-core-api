package es.in2.issuer.backend.backoffice.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RevokeCredentialRequest(
        @JsonProperty("credentialId") String credentialId,
        @JsonProperty("listId") int listId) {
}
