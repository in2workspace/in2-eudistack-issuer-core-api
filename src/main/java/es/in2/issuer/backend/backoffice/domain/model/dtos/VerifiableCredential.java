package es.in2.issuer.backend.backoffice.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record VerifiableCredential(
        @JsonProperty("format") String format,
        @JsonProperty("credential") String credential,
        @JsonProperty("c_nonce") String cNonce,
        @JsonProperty("c_nonce_expires_in") int cNonceExpiresIn) {
}
