package es.in2.issuer.backend.backoffice.domain.model.entities;

import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;

class SignatureConfigurationTest {

    @Test
    void testBuilderAndGetters() {
        UUID id = UUID.randomUUID();
        UUID cloudProviderId = UUID.randomUUID();
        SignatureConfiguration cfg = SignatureConfiguration.builder()
                .id(id)
                .organizationIdentifier("org-123")
                .enableRemoteSignature(true)
                .signatureMode(SignatureMode.CLOUD)
                .cloudProviderId(cloudProviderId)
                .clientId("client-xyz")
                .secretRelativePath("/path/to/secret")
                .credentialId("cred-789")
                .credentialName("MyCredential")
                .newTransaction(true)
                .build();

        assertEquals(id, cfg.getId());
        assertEquals("org-123", cfg.getOrganizationIdentifier());
        assertTrue(cfg.isEnableRemoteSignature());
        assertEquals(SignatureMode.CLOUD, cfg.getSignatureMode());
        assertEquals(cloudProviderId, cfg.getCloudProviderId());
        assertEquals("client-xyz", cfg.getClientId());
        assertEquals("/path/to/secret", cfg.getSecretRelativePath());
        assertEquals("cred-789", cfg.getCredentialId());
        assertEquals("MyCredential", cfg.getCredentialName());
        assertTrue(cfg.isNewTransaction());
    }

    @Test
    void testSetters() {
        SignatureConfiguration cfg = new SignatureConfiguration();

        UUID id = UUID.randomUUID();
        UUID cloudProviderId = UUID.randomUUID();
        cfg.setId(id);
        cfg.setOrganizationIdentifier("org-456");
        cfg.setEnableRemoteSignature(false);
        cfg.setSignatureMode(SignatureMode.LOCAL);
        cfg.setCloudProviderId(cloudProviderId);
        cfg.setClientId("client-abc");
        cfg.setSecretRelativePath("secret/path");
        cfg.setCredentialId("cred-123");
        cfg.setCredentialName("CredName");
        cfg.setNewTransaction(false);

        assertEquals(id, cfg.getId());
        assertEquals("org-456", cfg.getOrganizationIdentifier());
        assertFalse(cfg.isEnableRemoteSignature());
        assertEquals(SignatureMode.LOCAL, cfg.getSignatureMode());
        assertEquals(cloudProviderId, cfg.getCloudProviderId());
        assertEquals("client-abc", cfg.getClientId());
        assertEquals("secret/path", cfg.getSecretRelativePath());
        assertEquals("cred-123", cfg.getCredentialId());
        assertEquals("CredName", cfg.getCredentialName());
        assertFalse(cfg.isNewTransaction());
    }

    @Test
    void testIsNewWhenIdNull() {
        SignatureConfiguration cfg = new SignatureConfiguration();
        cfg.setNewTransaction(false);
        cfg.setId(null);
        // id == null => isNew true
        assertTrue(cfg.isNew());
    }

    @Test
    void testIsNewWhenNewTransactionTrue() {
        SignatureConfiguration cfg = new SignatureConfiguration();
        cfg.setId(UUID.randomUUID());
        cfg.setNewTransaction(true);
        // newTransaction true => isNew true even if id non-null
        assertTrue(cfg.isNew());
    }

    @Test
    void testIsNewWhenPersisted() {
        SignatureConfiguration cfg = new SignatureConfiguration();
        cfg.setId(UUID.randomUUID());
        cfg.setNewTransaction(false);
        // non-null id and newTransaction false => isNew false
        assertFalse(cfg.isNew());
    }
}
