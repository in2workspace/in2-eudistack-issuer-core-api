package es.in2.issuer.backend.backoffice.infrastructure.config.adapter.exception;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AzureConfigurationSettingExceptionTest {

    @Test
    void testConstructor() {
        String expectedMessage = "sample message";
        AzureConfigurationSettingException exception = new AzureConfigurationSettingException(expectedMessage);
        assertEquals(expectedMessage, exception.getMessage());
    }
}