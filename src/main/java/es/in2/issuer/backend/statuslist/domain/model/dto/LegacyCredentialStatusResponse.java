package es.in2.issuer.backend.statuslist.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

// Legacy model used to handle status list indexes with a PlainListEntry credentialStatus.
// TODO Remove once the last credential of this type expires in DOME.
public record LegacyCredentialStatusResponse(
        @JsonProperty("nonce") String credentialNonce) {
}
