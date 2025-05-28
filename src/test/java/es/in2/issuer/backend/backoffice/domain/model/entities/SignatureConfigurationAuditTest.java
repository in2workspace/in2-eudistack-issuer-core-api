package es.in2.issuer.backend.backoffice.domain.model.entities;


import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class SignatureConfigurationAuditTest {

    @Test
    void testBuilderAndGetters() {
        UUID id = UUID.randomUUID();
        String sigConfigId = "sigCfg-1";
        String userEmail = "user@domain.com";
        String orgId = "org-1";
        Instant now = Instant.parse("2025-05-13T10:15:30Z");
        String oldVals = "{\"a\":1}";
        String newVals = "{\"b\":2}";
        String rationale = "justification";
        boolean encrypted = true;

        SignatureConfigurationAudit audit = SignatureConfigurationAudit.builder()
                .id(id)
                .signatureConfigurationId(sigConfigId)
                .userEmail(userEmail)
                .organizationIdentifier(orgId)
                .instant(now)
                .oldValues(oldVals)
                .newValues(newVals)
                .rationale(rationale)
                .encrypted(encrypted)
                .build();

        assertEquals(id, audit.getId());
        assertEquals(sigConfigId, audit.getSignatureConfigurationId());
        assertEquals(userEmail, audit.getUserEmail());
        assertEquals(orgId, audit.getOrganizationIdentifier());
        assertEquals(now, audit.getInstant());
        assertEquals(oldVals, audit.getOldValues());
        assertEquals(newVals, audit.getNewValues());
        assertEquals(rationale, audit.getRationale());
        assertTrue(audit.isEncrypted());
    }

    @Test
    void testNoArgsAndSetters() {
        SignatureConfigurationAudit audit = new SignatureConfigurationAudit();

        UUID id = UUID.randomUUID();
        String sigConfigId = "sigCfg-2";
        String userEmail = "another@domain.com";
        String orgId = "org-2";
        Instant later = Instant.parse("2025-12-31T23:59:59Z");
        String oldVals = "{\"x\":9}";
        String newVals = "{\"y\":10}";
        String rationale = "reason";
        boolean encrypted = false;

        audit.setId(id);
        audit.setSignatureConfigurationId(sigConfigId);
        audit.setUserEmail(userEmail);
        audit.setOrganizationIdentifier(orgId);
        audit.setInstant(later);
        audit.setOldValues(oldVals);
        audit.setNewValues(newVals);
        audit.setRationale(rationale);
        audit.setEncrypted(encrypted);

        assertEquals(id, audit.getId());
        assertEquals(sigConfigId, audit.getSignatureConfigurationId());
        assertEquals(userEmail, audit.getUserEmail());
        assertEquals(orgId, audit.getOrganizationIdentifier());
        assertEquals(later, audit.getInstant());
        assertEquals(oldVals, audit.getOldValues());
        assertEquals(newVals, audit.getNewValues());
        assertEquals(rationale, audit.getRationale());
        assertFalse(audit.isEncrypted());
    }
}

