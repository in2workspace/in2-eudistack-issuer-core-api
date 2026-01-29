package es.in2.issuer.backend.oidc4vci.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialIssuerMetadataTest {

    @Test
    void shouldCreateMetadataWithSimpleConstructor() {
        // Arrange
        String credentialIssuer = "https://issuer.example.com";
        String issuanceEndpoint = "https://issuer.example.com/vci/v1/issuances";
        String credentialEndpoint = "https://issuer.example.com/oid4vci/v1/credential";
        String deferredCredentialEndpoint = "https://issuer.example.com/oid4vci/v1/deferrred-credential";
        String notificationEndpoint = "https://issuer.example.com/oid4vci/v1/notification";

        // Act
        CredentialIssuerMetadata metadata = new CredentialIssuerMetadata(
                credentialIssuer,
                issuanceEndpoint,
                credentialEndpoint,
                deferredCredentialEndpoint,
                notificationEndpoint,
                null
        );

        // Assert
        assertThat(metadata.credentialIssuer()).isEqualTo(credentialIssuer);
        assertThat(metadata.issuanceEndpoint()).isEqualTo(issuanceEndpoint);
        assertThat(metadata.credentialEndpoint()).isEqualTo(credentialEndpoint);
        assertThat(metadata.deferredCredentialEndpoint()).isEqualTo(deferredCredentialEndpoint);
        assertThat(metadata.credentialConfigurationsSupported()).isNull();
    }

    @Test
    void shouldCreateMetadataWithBuilderIncludingNestedStructures() {
        // Arrange
        var learCredentialEmployeeCredentialDefinition = CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                .type(Set.of("VerifiableCredential", "LEARCredentialEmployee"))
                .build();

        var proofSigninAlgValuesSupported = CredentialIssuerMetadata.CredentialConfiguration.ProofSigninAlgValuesSupported.builder()
                .proofSigningAlgValuesSupported(Set.of("ES256"))
                .build();

        var config = CredentialIssuerMetadata.CredentialConfiguration.builder()
                .format("jwt_vc_json")
                .scope("lear_credential_employee")
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                .credentialDefinition(learCredentialEmployeeCredentialDefinition)
                .proofTypesSupported(Map.of("jwt", proofSigninAlgValuesSupported))
                .build();

        var metadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("https://issuer.example.com")
                .issuanceEndpoint("https://issuer.example.com/vci/v1/issuances")
                .credentialEndpoint("https://issuer.example.com/credential")
                .deferredCredentialEndpoint("https://issuer.example.com/deferred")
                .credentialConfigurationsSupported(Map.of("LEARCredentialEmployee", config))
                .build();

        // Assert
        assertThat(metadata.credentialIssuer()).isEqualTo("https://issuer.example.com");
        assertThat(metadata.credentialConfigurationsSupported()).containsKey("LEARCredentialEmployee");

        var actualConfig = metadata.credentialConfigurationsSupported().get("LEARCredentialEmployee");
        assertThat(actualConfig.format()).isEqualTo("jwt_vc_json");
        assertThat(actualConfig.scope()).isEqualTo("lear_credential_employee");
        assertThat(actualConfig.cryptographicBindingMethodsSupported()).containsExactly("did:key");
        assertThat(actualConfig.credentialSigningAlgValuesSupported()).containsExactly("ES256");

        var actualDefinition = actualConfig.credentialDefinition();
        assertThat(actualDefinition.type()).containsExactlyInAnyOrder("VerifiableCredential", "LEARCredentialEmployee");

        var actualProof = actualConfig.proofTypesSupported().get("jwt");
        assertThat(actualProof.proofSigningAlgValuesSupported()).containsExactly("ES256");
    }

    @Test
    void shouldGenerateEqualsAndHashCodeCorrectly() {
        // Arrange
        var m1 = CredentialIssuerMetadata.builder()
                .credentialIssuer("issuer")
                .issuanceEndpoint("issuance")
                .credentialEndpoint("credential")
                .deferredCredentialEndpoint("deferred")
                .build();

        var m2 = CredentialIssuerMetadata.builder()
                .credentialIssuer("issuer")
                .issuanceEndpoint("issuance")
                .credentialEndpoint("credential")
                .deferredCredentialEndpoint("deferred")
                .build();

        // Assert
        assertThat(m1).isEqualTo(m2);
        assertThat(m1.hashCode()).hasSameHashCodeAs(m2.hashCode());
    }

}
