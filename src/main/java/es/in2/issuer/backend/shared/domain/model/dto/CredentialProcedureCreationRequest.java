package es.in2.issuer.backend.shared.domain.model.dto;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import lombok.Builder;

import java.sql.Timestamp;

@Builder
public record CredentialProcedureCreationRequest(
        String credentialId,
        String organizationIdentifier,
        String credentialDecoded,
        CredentialType credentialType,
        String subject,
        Timestamp validUntil,
        String operationMode,
        String signatureMode,
        String ownerEmail
        )
{
}
