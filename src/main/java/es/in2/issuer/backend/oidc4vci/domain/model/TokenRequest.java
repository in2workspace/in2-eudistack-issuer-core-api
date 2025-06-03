package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record TokenRequest(
        @JsonProperty(value = "grant_type", required = true) String grantType,
        @JsonProperty(value = "pre-authorized_code", required = true) String preAuthorizedCode,
        @JsonProperty(value = "tx_code", required = true) String txCode) {
}
