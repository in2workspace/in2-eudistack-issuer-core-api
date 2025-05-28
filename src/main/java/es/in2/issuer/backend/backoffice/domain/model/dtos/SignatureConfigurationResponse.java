package es.in2.issuer.backend.backoffice.domain.model.dtos;


import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;
import lombok.Builder;

import java.util.UUID;

@Builder
public record SignatureConfigurationResponse(UUID id,
                                             String organizationIdentifier,
                                             boolean enableRemoteSignature,
                                             SignatureMode signatureMode,
                                             UUID cloudProviderId,
                                             String clientId,
                                             String credentialId,
                                             String credentialName,
                                             String vaultHashedSecretValues,
                                             String secretRelativePath
) {
}
