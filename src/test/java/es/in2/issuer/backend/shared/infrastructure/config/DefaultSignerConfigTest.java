package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.adapter.ConfigAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.adapter.factory.ConfigAdapterFactory;
import es.in2.issuer.backend.shared.infrastructure.config.properties.DefaultSignerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class DefaultSignerConfigTest {

    @Mock
    private ConfigAdapter configAdapter;

    @Mock
    private ConfigAdapterFactory configAdapterFactory;

    private DefaultSignerConfig defaultSignerConfig;

    @BeforeEach
    void setUp() {
        // Initialize the real DefaultSignerProperties with test values
        DefaultSignerProperties defaultSignerProperties = new DefaultSignerProperties(
                "CommonName",
                "Country",
                "email",
                "OrgId",
                "Organization",
                "SerialNumber"
        );

        // Mock configAdapterFactory behavior to return the mocked configAdapter
        lenient().when(configAdapterFactory.getAdapter()).thenReturn(configAdapter);

        // Mock configAdapter behavior
        lenient().when(configAdapter.getConfiguration(anyString())).thenAnswer(invocation -> invocation.getArgument(0));

        defaultSignerConfig = new DefaultSignerConfig(configAdapterFactory, defaultSignerProperties);
    }

    @Test
    void testGetCommonName() {
        String result = defaultSignerConfig.getCommonName();
        assertEquals("CommonName", result);
    }

    @Test
    void testGetCountry() {
        String result = defaultSignerConfig.getCountry();
        assertEquals("Country", result);
    }

    @Test
    void testGetEmail() {
        String result = defaultSignerConfig.getEmail();
        assertEquals("email", result);
    }

    @Test
    void testGetOrganizationIdentifier() {
        String result = defaultSignerConfig.getOrganizationIdentifier();
        assertEquals("OrgId", result);
    }

    @Test
    void testGetOrganization() {
        String result = defaultSignerConfig.getOrganization();
        assertEquals("Organization", result);
    }

    @Test
    void testGetSerialNumber() {
        String result = defaultSignerConfig.getSerialNumber();
        assertEquals("SerialNumber", result);
    }
}
