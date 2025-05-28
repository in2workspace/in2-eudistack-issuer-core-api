package es.in2.issuer.backend.backoffice.domain.model.dtos;

import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;

import java.util.UUID;

public record SignatureConfigWithProviderName(UUID id,
                                              String organizationIdentifier,
                                              boolean enableRemoteSignature,
                                              SignatureMode signatureMode,
                                              String cloudProviderName,
                                              String clientId,
                                              String credentialId,
                                              String credentialName
) {

}
