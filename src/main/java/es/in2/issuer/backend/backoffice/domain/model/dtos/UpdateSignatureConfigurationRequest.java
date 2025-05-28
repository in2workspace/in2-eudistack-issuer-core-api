package es.in2.issuer.backend.backoffice.domain.model.dtos;

import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;
import lombok.Builder;

import java.util.UUID;

@Builder
public record UpdateSignatureConfigurationRequest (UUID id,
                                                   String organizationIdentifier,
                                                   Boolean enableRemoteSignature,
                                                   SignatureMode signatureMode,
                                                   UUID cloudProviderId,
                                                   String clientId,
                                                   String credentialId,
                                                   String credentialName,
                                                   String secretRelativePath,
                                                   String clientSecret,
                                                   String credentialPassword,
                                                   String secret,
                                                   String rationale) {
    public CompleteSignatureConfiguration toCompleteSignatureConfiguration() {
        return CompleteSignatureConfiguration.builder()
                .id(id)
                .organizationIdentifier(organizationIdentifier)
                .enableRemoteSignature(enableRemoteSignature)
                .signatureMode(signatureMode)
                .cloudProviderId(cloudProviderId)
                .clientId(clientId)
                .credentialId(credentialId)
                .credentialName(credentialName)
                .secretRelativePath(secretRelativePath)
                .clientSecret(clientSecret)
                .credentialPassword(credentialPassword)
                .secret(secret)
                .build();
    }
}
