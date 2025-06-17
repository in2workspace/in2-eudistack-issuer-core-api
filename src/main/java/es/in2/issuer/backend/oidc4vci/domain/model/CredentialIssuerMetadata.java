package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.Map;
import java.util.Set;

@Builder
public record CredentialIssuerMetadata(
        @JsonProperty(value = "credential_issuer", required = true) String credentialIssuer,
        @JsonProperty(value = "issuance_endpoint", required = true) String issuanceEndpoint,
        @JsonProperty(value = "credential_endpoint", required = true) String credentialEndpoint,
        @JsonProperty("deferred_credential_endpoint") String deferredCredentialEndpoint,
        @JsonProperty(value = "credential_configurations_supported", required = true) Map<String, CredentialConfiguration> credentialConfigurationsSupported
) {

    @Builder
    public record CredentialConfiguration(
            @JsonProperty("format") String format,
            @JsonProperty("scope") String scope,
            @JsonProperty("cryptographic_binding_methods_supported") Set<String> cryptographicBindingMethodsSupported,
            @JsonProperty("credential_signing_alg_values_supported") Set<String> credentialSigningAlgValuesSupported,
            @JsonProperty("credential_definition") CredentialDefinition credentialDefinition,
            @JsonProperty("proof_types_supported") Map<String, ProofSigninAlgValuesSupported> proofTypesSupported
    ) {

        @Builder
        public record CredentialDefinition(@JsonProperty("type") Set<String> type) {
        }

        @Builder
        public record ProofSigninAlgValuesSupported(
                @JsonProperty("proof_signing_alg_values_supported") Set<String> proofSigningAlgValuesSupported) {
        }

    }

}
