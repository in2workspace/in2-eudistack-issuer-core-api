package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.junit.jupiter.api.Test;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SIGNATURE_REMOTE_TYPE_SERVER;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RemoteSignaturePropertiesTest {
    @Test
    void testRemoteSignatureProperties() {
        RemoteSignatureProperties.Paths paths = new RemoteSignatureProperties.Paths("signPath");
        RemoteSignatureProperties remoteSignatureProperties = new RemoteSignatureProperties(SIGNATURE_REMOTE_TYPE_SERVER,"domain", paths, "clientId", "clientSecret", "credentialId", "credentialPassword");

        assertEquals(SIGNATURE_REMOTE_TYPE_SERVER, remoteSignatureProperties.type());
        assertEquals("domain", remoteSignatureProperties.url());
        assertEquals(paths, remoteSignatureProperties.paths());
        assertEquals("clientId", remoteSignatureProperties.clientId());
        assertEquals("clientSecret", remoteSignatureProperties.clientSecret());
        assertEquals("credentialId", remoteSignatureProperties.credentialId());
        assertEquals("credentialPassword", remoteSignatureProperties.credentialPassword());
    }
}