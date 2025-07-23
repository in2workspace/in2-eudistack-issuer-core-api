package es.in2.issuer.backend.shared.domain.model.entities;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialProcedureTest {

    @Test
    void testCredentialProcedure() {
        UUID procedureId = UUID.randomUUID();
        UUID credentialId = UUID.randomUUID();
        String credentialFormat = "testFormat";
        String credentialDecoded = "testDecoded";
        String credentialEncoded = "testEncoded";
        CredentialStatusEnum credentialStatusEnum = CredentialStatusEnum.VALID;
        String organizationIdentifier = "testOrganizationIdentifier";
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        Timestamp validUntil = new Timestamp(System.currentTimeMillis() + 1000);

        CredentialProcedure credentialProcedure = CredentialProcedure.builder()
                .procedureId(procedureId)
                .credentialId(credentialId)
                .credentialFormat(credentialFormat)
                .credentialDecoded(credentialDecoded)
                .credentialEncoded(credentialEncoded)
                .credentialStatus(credentialStatusEnum)
                .organizationIdentifier(organizationIdentifier)
                .updatedAt(timestamp)
                .validUntil(validUntil)
                .build();

        assertEquals(procedureId, credentialProcedure.getProcedureId());
        assertEquals(credentialId, credentialProcedure.getCredentialId());
        assertEquals(credentialFormat, credentialProcedure.getCredentialFormat());
        assertEquals(credentialDecoded, credentialProcedure.getCredentialDecoded());
        assertEquals(credentialEncoded, credentialProcedure.getCredentialEncoded());
        assertEquals(credentialStatusEnum, credentialProcedure.getCredentialStatus());
        assertEquals(organizationIdentifier, credentialProcedure.getOrganizationIdentifier());
        assertEquals(timestamp, credentialProcedure.getUpdatedAt());
        assertEquals(validUntil, credentialProcedure.getValidUntil());
    }

    @Test
    void testSettersAndGetters() {
        CredentialProcedure credentialProcedure = new CredentialProcedure();
        UUID procedureId = UUID.randomUUID();
        UUID credentialId = UUID.randomUUID();
        String credentialFormat = "format";
        String credentialDecoded = "decoded";
        String credentialEncoded = "encoded";
        CredentialStatusEnum credentialStatusEnum = CredentialStatusEnum.VALID;
        String organizationIdentifier = "orgId";
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        Timestamp validUntil = new Timestamp(System.currentTimeMillis() + 1000);

        credentialProcedure.setProcedureId(procedureId);
        credentialProcedure.setCredentialId(credentialId);
        credentialProcedure.setCredentialFormat(credentialFormat);
        credentialProcedure.setCredentialDecoded(credentialDecoded);
        credentialProcedure.setCredentialEncoded(credentialEncoded);
        credentialProcedure.setCredentialStatus(credentialStatusEnum);
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);
        credentialProcedure.setUpdatedAt(timestamp);
        credentialProcedure.setValidUntil(validUntil);

        assertEquals(procedureId, credentialProcedure.getProcedureId());
        assertEquals(credentialId, credentialProcedure.getCredentialId());
        assertEquals(credentialFormat, credentialProcedure.getCredentialFormat());
        assertEquals(credentialDecoded, credentialProcedure.getCredentialDecoded());
        assertEquals(credentialEncoded, credentialProcedure.getCredentialEncoded());
        assertEquals(credentialStatusEnum, credentialProcedure.getCredentialStatus());
        assertEquals(organizationIdentifier, credentialProcedure.getOrganizationIdentifier());
        assertEquals(timestamp, credentialProcedure.getUpdatedAt());
        assertEquals(validUntil, credentialProcedure.getValidUntil());
    }

//    @Test
//    void testToString() {
//        CredentialProcedure credentialProcedure = CredentialProcedure.builder().build();
//
//        String expected = "CredentialProcedure(procedureId=" + credentialProcedure.getProcedureId() +
//                ", credentialId=" + credentialProcedure.getCredentialId() +
//                ", credentialFormat=" + credentialProcedure.getCredentialFormat() +
//                ", credentialDecoded=" + credentialProcedure.getCredentialDecoded() +
//                ", credentialEncoded=" + credentialProcedure.getCredentialEncoded() +
//                ", credentialStatus=" + credentialProcedure.getCredentialStatus() +
//                ", organizationIdentifier=" + credentialProcedure.getOrganizationIdentifier() +
//                ", updatedAt=" + credentialProcedure.getUpdatedAt() +
//                ", subject=" + credentialProcedure.getSubject() +
//                ", credentialType=" + credentialProcedure.getCredentialType() +
//                ", validUntil=" + credentialProcedure.getValidUntil() +
//                ", operationMode=" + credentialProcedure.getOperationMode() +
//                ", signatureMode=" + credentialProcedure.getSignatureMode() +
//                ")";
//        assertEquals(expected, credentialProcedure.toString());
//    }
}