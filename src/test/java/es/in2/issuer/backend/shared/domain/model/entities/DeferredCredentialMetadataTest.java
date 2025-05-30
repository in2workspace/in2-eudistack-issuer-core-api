package es.in2.issuer.backend.shared.domain.model.entities;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DeferredCredentialMetadataTest {

    @Test
    void testDeferredCredentialMetadata() {
        UUID uuid = UUID.randomUUID();
        String transactionCode = "testTransactionCode";
        String authServerNonce = "testAuthServerNonce";
        String transactionId = "testTransactionId";
        UUID procedureId = UUID.randomUUID();
        String vc = "testVc";
        String vcFormat = "testVcFormat";

        DeferredCredentialMetadata deferredCredentialMetadata = DeferredCredentialMetadata.builder()
                .id(uuid)
                .transactionCode(transactionCode)
                .authServerNonce(authServerNonce)
                .transactionId(transactionId)
                .procedureId(procedureId)
                .vc(vc)
                .vcFormat(vcFormat)
                .build();

        assertEquals(uuid, deferredCredentialMetadata.getId());
        assertEquals(transactionCode, deferredCredentialMetadata.getTransactionCode());
        assertEquals(authServerNonce, deferredCredentialMetadata.getAuthServerNonce());
        assertEquals(transactionId, deferredCredentialMetadata.getTransactionId());
        assertEquals(procedureId, deferredCredentialMetadata.getProcedureId());
        assertEquals(vc, deferredCredentialMetadata.getVc());
        assertEquals(vcFormat, deferredCredentialMetadata.getVcFormat());
    }

    @Test
    void testSettersAndGetters() {
        DeferredCredentialMetadata deferredCredentialMetadata = new DeferredCredentialMetadata();

        UUID uuid = UUID.randomUUID();
        String transactionCode = "transactionCode";
        String authServerNonce = "authServerNonce";
        String transactionId = "transactionId";
        UUID procedureId = UUID.randomUUID();
        String vc = "jwtCredential";
        String vcFormat = "vcFormat";

        deferredCredentialMetadata.setId(uuid);
        deferredCredentialMetadata.setTransactionCode(transactionCode);
        deferredCredentialMetadata.setAuthServerNonce(authServerNonce);
        deferredCredentialMetadata.setTransactionId(transactionId);
        deferredCredentialMetadata.setProcedureId(procedureId);
        deferredCredentialMetadata.setVc(vc);
        deferredCredentialMetadata.setVcFormat(vcFormat);

        assertEquals(uuid, deferredCredentialMetadata.getId());
        assertEquals(transactionCode, deferredCredentialMetadata.getTransactionCode());
        assertEquals(authServerNonce, deferredCredentialMetadata.getAuthServerNonce());
        assertEquals(transactionId, deferredCredentialMetadata.getTransactionId());
        assertEquals(procedureId, deferredCredentialMetadata.getProcedureId());
        assertEquals(vc, deferredCredentialMetadata.getVc());
        assertEquals(vcFormat, deferredCredentialMetadata.getVcFormat());
    }

    @Test
    void testToString() {
        DeferredCredentialMetadata deferredCredentialMetadata = DeferredCredentialMetadata.builder().build();

        String expected = "DeferredCredentialMetadata(id=" + deferredCredentialMetadata.getId() +
                ", transactionCode=" + deferredCredentialMetadata.getTransactionCode() +
                ", authServerNonce=" + deferredCredentialMetadata.getAuthServerNonce() +
                ", transactionId=" + deferredCredentialMetadata.getTransactionId() +
                ", procedureId=" + deferredCredentialMetadata.getProcedureId() +
                ", vc=" + deferredCredentialMetadata.getVc() +
                ", vcFormat=" + deferredCredentialMetadata.getVcFormat() +
                ", operationMode=" + deferredCredentialMetadata.getOperationMode() +
                ", responseUri=" + deferredCredentialMetadata.getResponseUri() + ")";
        assertEquals(expected, deferredCredentialMetadata.toString());
    }
}