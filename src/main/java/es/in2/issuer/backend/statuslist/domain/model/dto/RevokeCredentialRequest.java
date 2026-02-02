package es.in2.issuer.backend.statuslist.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RevokeCredentialRequest(
        @JsonProperty("procedureId") String procedureId,
        @JsonProperty("listId") int listId) {
}