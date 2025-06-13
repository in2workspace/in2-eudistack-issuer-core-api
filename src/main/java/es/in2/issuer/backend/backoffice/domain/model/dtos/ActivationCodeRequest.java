package es.in2.issuer.backend.backoffice.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record ActivationCodeRequest(
        @JsonProperty("activationCode") String activationCode,
        @JsonProperty("c_activationCode") String cActivationCode
) {
}
