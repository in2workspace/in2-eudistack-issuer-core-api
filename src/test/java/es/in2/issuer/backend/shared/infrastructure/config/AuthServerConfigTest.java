package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.adapter.ConfigAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.adapter.factory.ConfigAdapterFactory;
import es.in2.issuer.backend.shared.infrastructure.config.properties.AuthServerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class AuthServerConfigTest {

    @Mock
    private ConfigAdapter configAdapter;

    @Mock
    private ConfigAdapterFactory configAdapterFactory;

    @Mock
    private AuthServerProperties authServerProperties;

    private AuthServerConfig authServerConfig;

    @BeforeEach
    void setUp() {
        AuthServerProperties.Paths paths = new AuthServerProperties.Paths("issuerDid", "jwtDecoderPath", "jwtDecoderLocalPath", "jwtValidatorPath", "preAuthorizedCodePath", "tokenPath", "nonceValidationPath");
        AuthServerProperties.Client client = new AuthServerProperties.Client("clientId", "username", "password");

        lenient().when(authServerProperties.externalUrl()).thenReturn("externalDomain");
        lenient().when(authServerProperties.internalUrl()).thenReturn("internalDomain");
        lenient().when(authServerProperties.realm()).thenReturn("realm");
        lenient().when(authServerProperties.paths()).thenReturn(paths);
        lenient().when(authServerProperties.client()).thenReturn(client);

        // Mock configAdapterFactory behavior to return the mocked configAdapter
        lenient().when(configAdapterFactory.getAdapter()).thenReturn(configAdapter);

        // Mock configAdapter behavior
        lenient().when(configAdapter.getConfiguration(anyString())).thenAnswer(invocation -> invocation.getArgument(0));

        // Create authServerConfig after setting up the mocks
        authServerConfig = new AuthServerConfig(configAdapterFactory, authServerProperties);
    }

    @Test
    void testGetAuthServerExternalDomain() {
        String result = authServerConfig.getAuthServerExternalDomain();
        assertEquals("externalDomain", result);
    }

    @Test
    void testGetAuthServerInternalDomain() {
        String result = authServerConfig.getAuthServerInternalDomain();
        assertEquals("internalDomain", result);
    }

    @Test
    void testGetAuthServerClientId() {
        String result = authServerConfig.getAuthServerClientId();
        assertEquals("clientId", result);
    }

    @Test
    void testGetAuthServerUsername() {
        String result = authServerConfig.getAuthServerUsername();
        assertEquals("username", result);
    }

    @Test
    void testGetAuthServerUserPassword() {
        String result = authServerConfig.getAuthServerUserPassword();
        assertEquals("password", result);
    }

    @Test
    void testGetAuthServerRealm() {
        String result = authServerConfig.getAuthServerRealm();
        assertEquals("realm", result);
    }

    @Test
    void testGetAuthServerIssuerDid() {
        String result = authServerConfig.getAuthServerIssuerDid();
        assertEquals("issuerDid", result);
    }

    @Test
    void testGetAuthServerJwtDecoderPath() {
        String result = authServerConfig.getAuthServerJwtDecoderPath();
        assertEquals("jwtDecoderPath", result);
    }

    @Test
    void testGetAuthServerJwtDecoderLocalPath() {
        String result = authServerConfig.getAuthServerJwtDecoderLocalPath();
        assertEquals("jwtDecoderLocalPath", result);
    }

    @Test
    void testGetAuthServerJwtValidatorPath() {
        String result = authServerConfig.getAuthServerJwtValidatorPath();
        assertEquals("jwtValidatorPath", result);
    }

    @Test
    void testGetAuthServerPreAuthorizedCodePath() {
        String result = authServerConfig.getAuthServerPreAuthorizedCodePath();
        assertEquals("preAuthorizedCodePath", result);
    }

    @Test
    void testGetAuthServerTokenPath() {
        String result = authServerConfig.getAuthServerTokenPath();
        assertEquals("tokenPath", result);
    }

    @Test
    void testGetAuthServerNonceValidationPath() {
        String result = authServerConfig.getAuthServerNonceValidationPath();
        assertEquals("nonceValidationPath", result);
    }

    @Test
    void testGetJwtDecoder() {
        String result = authServerConfig.getJwtDecoder();
        assertEquals("internalDomainjwtDecoderPath", result);
    }

    @Test
    void testGetJwtDecoderLocal() {
        String result = authServerConfig.getJwtDecoderLocal();
        assertEquals("internalDomainjwtDecoderLocalPath", result);
    }

    @Test
    void testGetPreAuthCodeUri() {
        String result = authServerConfig.getPreAuthCodeUri();
        assertEquals("internalDomainpreAuthorizedCodePath", result);
    }

    @Test
    void testGetTokenUri() {
        String result = authServerConfig.getTokenUri();
        assertEquals("internalDomaintokenPath", result);
    }

    @Test
    void testGetJwtValidator() {
        String result = authServerConfig.getJwtValidator();
        assertEquals("externalDomainjwtValidatorPath", result);
    }
}