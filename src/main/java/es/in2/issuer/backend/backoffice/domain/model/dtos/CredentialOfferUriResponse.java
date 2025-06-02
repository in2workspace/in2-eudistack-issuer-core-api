package es.in2.issuer.backend.backoffice.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialOfferUriResponse(
        @JsonProperty("credential_offer_uri") String credentialOfferUri,
        @JsonProperty("c_activation_code") String cActivationCode,
        @JsonProperty("c_activation_code_expires_in") int cActivationCodeExpiresIn
) {
}
