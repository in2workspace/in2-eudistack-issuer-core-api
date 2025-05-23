package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.adapter.ConfigAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.adapter.factory.ConfigAdapterFactory;
import es.in2.issuer.backend.shared.infrastructure.config.properties.RemoteSignatureProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RemoteSignatureConfigTest {

    @Mock
    private ConfigAdapterFactory configAdapterFactory;

    @Mock
    private ConfigAdapter configAdapter;

    @Mock
    private RemoteSignatureProperties remoteSignatureProperties;

    private RemoteSignatureConfig remoteSignatureConfig;

    @BeforeEach
    void setUp() {
        when(configAdapterFactory.getAdapter()).thenReturn(configAdapter);
        remoteSignatureConfig = new RemoteSignatureConfig(configAdapterFactory, remoteSignatureProperties);
    }

    @Test
    void testGetRemoteSignatureDomain() {
        // Arrange
        String expectedDomain = "https://signature.example.com";
        when(remoteSignatureProperties.url()).thenReturn("remote.signature.domain");
        when(configAdapter.getConfiguration("remote.signature.domain")).thenReturn(expectedDomain);

        // Act
        String actualDomain = remoteSignatureConfig.getRemoteSignatureDomain();

        // Assert
        assertEquals(expectedDomain, actualDomain);
    }

    @Test
    void testGetRemoteSignatureSignPath() {
        // Arrange
        String expectedPath = "/api/sign";
        RemoteSignatureProperties.Paths paths = mock(RemoteSignatureProperties.Paths.class);
        when(remoteSignatureProperties.paths()).thenReturn(paths);
        when(paths.signPath()).thenReturn("remote.signature.sign.path");
        when(configAdapter.getConfiguration("remote.signature.sign.path")).thenReturn(expectedPath);

        // Act
        String actualPath = remoteSignatureConfig.getRemoteSignatureSignPath();

        // Assert
        assertEquals(expectedPath, actualPath);
    }

    @Test
    void testGetRemoteSignatureClientId() {
        // Arrange
        String expectedClientId = "client_id";
        when(remoteSignatureProperties.clientId()).thenReturn("remote.signature.client-id");
        when(configAdapter.getConfiguration("remote.signature.client-id")).thenReturn(expectedClientId);

        // Act
        String actualClientId = remoteSignatureConfig.getRemoteSignatureClientId();

        // Assert
        assertEquals(expectedClientId, actualClientId);
    }

    @Test
    void testGetRemoteSignatureClientSecret() {
        // Arrange
        String expectedClientSecret = "client_secret";
        when(remoteSignatureProperties.clientSecret()).thenReturn("remote.signature.client-secret");
        when(configAdapter.getConfiguration("remote.signature.client-secret")).thenReturn(expectedClientSecret);

        // Act
        String actualClientSecret = remoteSignatureConfig.getRemoteSignatureClientSecret();

        // Assert
        assertEquals(expectedClientSecret, actualClientSecret);
    }

    @Test
    void testGetRemoteSignatureCredentialId() {
        // Arrange
        String expectedCredentialId = "credential_id";
        when(remoteSignatureProperties.credentialId()).thenReturn("remote.signature.credential-id");
        when(configAdapter.getConfiguration("remote.signature.credential-id")).thenReturn(expectedCredentialId);

        // Act
        String actualCredentialId = remoteSignatureConfig.getRemoteSignatureCredentialId();

        // Assert
        assertEquals(expectedCredentialId, actualCredentialId);
    }

    @Test
    void testGetRemoteSignatureCredentialPassword() {
        // Arrange
        String expectedCredentialPassword = "credential_password";
        when(remoteSignatureProperties.credentialPassword()).thenReturn("remote.signature.credential-password");
        when(configAdapter.getConfiguration("remote.signature.credential-password")).thenReturn(expectedCredentialPassword);

        // Act
        String actualCredentialPassword = remoteSignatureConfig.getRemoteSignatureCredentialPassword();

        // Assert
        assertEquals(expectedCredentialPassword, actualCredentialPassword);
    }
}