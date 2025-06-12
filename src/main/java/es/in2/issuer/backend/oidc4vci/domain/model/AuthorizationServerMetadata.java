package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.Set;

@Builder
public record AuthorizationServerMetadata(
        @JsonProperty("issuer") String issuer,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("response_types_supported") Set<String> responseTypesSupported,
        @JsonProperty("pre-authorized_grant_anonymous_access_supported") boolean preAuthorizedGrantAnonymousAccessSupported
) {
}
