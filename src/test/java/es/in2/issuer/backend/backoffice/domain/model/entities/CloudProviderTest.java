package es.in2.issuer.backend.backoffice.domain.model.entities;


import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CloudProviderTest {
    @ParameterizedTest
    @ValueSource(strings = {"AWS", "Azure", "GoogleCloud"})
    void cloudProvider_initializesCorrectlyWithValidProvider(String validProvider) {
        CloudProvider cloudProvider = CloudProvider.builder()
                .id(UUID.randomUUID())
                .provider(validProvider)
                .url("https://valid-url.com")
                .authMethod("OAuth2")
                .authGrantType("client_credentials")
                .requiresTOTP(true)
                .build();

        assertNotNull(cloudProvider.getId());
        assertEquals(validProvider, cloudProvider.getProvider());
        assertEquals("https://valid-url.com", cloudProvider.getUrl());
        assertEquals("OAuth2", cloudProvider.getAuthMethod());
        assertEquals("client_credentials", cloudProvider.getAuthGrantType());
        assertTrue(cloudProvider.isRequiresTOTP());
    }
}
