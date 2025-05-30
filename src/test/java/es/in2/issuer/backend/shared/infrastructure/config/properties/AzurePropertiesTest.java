package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AzurePropertiesTest {
    @Test
    void testAzureProperties() {
        AzureProperties.AzurePropertiesLabel azurePropertiesLabel = new AzureProperties.AzurePropertiesLabel("global");
        AzureProperties azureProperties = new AzureProperties("endpoint", azurePropertiesLabel);

        assertEquals("endpoint", azureProperties.endpoint());
        assertEquals(azurePropertiesLabel, azureProperties.label());
    }
}