package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;
import static es.in2.issuer.backend.shared.domain.util.HttpUtils.ensureUrlHasProtocol;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialIssuerMetadataServiceImpl implements CredentialIssuerMetadataService {

    private final AppConfig appConfig;
    private static final String ES256_SIGNING_ALG_VALUE = "ES256";

    @Override
    public Mono<CredentialIssuerMetadata> getCredentialIssuerMetadata(String processId) {
        String credentialIssuerUrl = ensureUrlHasProtocol(appConfig.getIssuerBackendUrl());
        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer(credentialIssuerUrl)
                .issuanceEndpoint(credentialIssuerUrl + VCI_ISSUANCES_PATH)
                .credentialEndpoint(credentialIssuerUrl + OID4VCI_CREDENTIAL_PATH)
                .deferredCredentialEndpoint(credentialIssuerUrl + OID4VCI_DEFERRED_CREDENTIAL_PATH)
                .credentialConfigurationsSupported(Map.of(
                        LEAR_CREDENTIAL_EMPLOYEE, buildLearCredentialEmployeeCredentialConfiguration(),
                        LEAR_CREDENTIAL_MACHINE, buildLearCredentialMachineCredentialConfiguration(),
                        LABEL_CREDENTIAL, buildLabelCredentialConfiguration()
                ))
                .build();
        return Mono.just(credentialIssuerMetadata);
    }

    private CredentialIssuerMetadata.CredentialConfiguration buildLearCredentialEmployeeCredentialConfiguration() {
        return CredentialIssuerMetadata.CredentialConfiguration.builder()
                .format(JWT_VC_JSON)
                .scope("lear_credential_employee")
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of(ES256_SIGNING_ALG_VALUE))
                .credentialDefinition(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                        .type(Set.of(VERIFIABLE_CREDENTIAL, LEAR_CREDENTIAL_EMPLOYEE))
                        .build())
                .proofTypesSupported(Map.of("jwt", CredentialIssuerMetadata.CredentialConfiguration.ProofSigninAlgValuesSupported.builder()
                        .proofSigningAlgValuesSupported(Set.of(ES256_SIGNING_ALG_VALUE))
                        .build()))
                .build();
    }

    private CredentialIssuerMetadata.CredentialConfiguration buildLearCredentialMachineCredentialConfiguration() {
        return CredentialIssuerMetadata.CredentialConfiguration.builder()
                .format(JWT_VC_JSON)
                .scope("lear_credential_machine")
                .credentialSigningAlgValuesSupported(Set.of(ES256_SIGNING_ALG_VALUE))
                .credentialDefinition(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                        .type(Set.of(VERIFIABLE_CREDENTIAL, LEAR_CREDENTIAL_MACHINE))
                        .build())
                .build();
    }

    private CredentialIssuerMetadata.CredentialConfiguration buildLabelCredentialConfiguration() {
        return CredentialIssuerMetadata.CredentialConfiguration.builder()
                .format(JWT_VC_JSON)
                .scope("gx:LabelCredential")
                .credentialSigningAlgValuesSupported(Set.of(ES256_SIGNING_ALG_VALUE))
                .credentialDefinition(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                        .type(Set.of(VERIFIABLE_CREDENTIAL, LABEL_CREDENTIAL))
                        .build())
                .build();
    }

}
