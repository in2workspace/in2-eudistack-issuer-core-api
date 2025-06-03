package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.Set;

@Builder
public record AuthorizationServerMetadata(
        @JsonProperty(value = "issuer", required = true) String issuer,
        @JsonProperty(value = "token_endpoint", required = true) String tokenEndpoint,
        @JsonProperty(value = "response_types_supported", required = true) Set<String> responseTypesSupported,
        @JsonProperty(value = "pre-authorized_grant_anonymous_access_supported", required = true) boolean preAuthorizedGrantAnonymousAccessSupported
) {
}
