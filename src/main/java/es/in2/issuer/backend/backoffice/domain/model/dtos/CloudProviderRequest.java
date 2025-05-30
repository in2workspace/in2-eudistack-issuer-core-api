package es.in2.issuer.backend.backoffice.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CloudProviderRequest (
    @JsonProperty("provider")
    String provider,
    @JsonProperty("url")
    String url,
    @JsonProperty("authMethod")
    String authMethod,
    @JsonProperty("authGrantType")
    String authGrantType,
    @JsonProperty("clientId")
    boolean requiresTOTP
    ){
}
