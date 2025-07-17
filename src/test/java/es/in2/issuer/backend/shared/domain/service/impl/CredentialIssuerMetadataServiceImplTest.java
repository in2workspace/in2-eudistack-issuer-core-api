package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.util.Constants;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.VERIFIABLE_CREDENTIAL;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_CREDENTIAL_PATH;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_DEFERRED_CREDENTIAL_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerMetadataServiceImplTest {

    private static final String PROCESS_ID = "b731b463-7473-4f97-be7a-658ec0b5dbc9";
    private static final String ISSUER_URL = "https://issuer.example.com";

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private CredentialIssuerMetadataServiceImpl credentialIssuerMetadataService;

    @Test
    void shouldGetCredentialIssuerMetadataSuccessfully() {
        // Arrange
        when(appConfig.getIssuerBackendUrl()).thenReturn(ISSUER_URL);
        // Act
        var resultMono = credentialIssuerMetadataService.getCredentialIssuerMetadata(PROCESS_ID);
        // Assert
        StepVerifier.create(resultMono)
                .assertNext(metadata -> {
                    assertThat(metadata.credentialIssuer()).isEqualTo(ISSUER_URL);
                    assertThat(metadata.credentialEndpoint()).isEqualTo(ISSUER_URL + OID4VCI_CREDENTIAL_PATH);
                    assertThat(metadata.deferredCredentialEndpoint()).isEqualTo(ISSUER_URL + OID4VCI_DEFERRED_CREDENTIAL_PATH);

                    Map<String, CredentialIssuerMetadata.CredentialConfiguration> configs = metadata.credentialConfigurationsSupported();
                    assertThat(configs).containsKeys(LEAR_CREDENTIAL_EMPLOYEE);

                    CredentialIssuerMetadata.CredentialConfiguration learCredentialEmployeeConfig = configs.get(LEAR_CREDENTIAL_EMPLOYEE);
                    assertThat(learCredentialEmployeeConfig.format()).isEqualTo(Constants.JWT_VC_JSON);
                    assertThat(learCredentialEmployeeConfig.scope()).isEqualTo("lear_credential_employee");
                    assertThat(learCredentialEmployeeConfig.cryptographicBindingMethodsSupported()).containsExactly("did:key");
                    assertThat(learCredentialEmployeeConfig.credentialSigningAlgValuesSupported()).containsExactly("ES256");

                    CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition definition = learCredentialEmployeeConfig.credentialDefinition();
                    assertThat(definition).isNotNull();
                    assertThat(definition.type()).containsExactlyInAnyOrder(VERIFIABLE_CREDENTIAL, LEAR_CREDENTIAL_EMPLOYEE);

                    Map<String, CredentialIssuerMetadata.CredentialConfiguration.ProofSigninAlgValuesSupported> proofTypes = learCredentialEmployeeConfig.proofTypesSupported();
                    assertThat(proofTypes).containsKey("jwt");
                    assertThat(proofTypes.get("jwt").proofSigningAlgValuesSupported()).containsExactly("ES256");
                })
                .verifyComplete();
    }

}
