package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class CorsPropertiesTest {
    @Test
    void corsProperties_whenDefaultAllowedOriginsProvided_returnsDefaultAllowedOrigins() {
        List<String> defaultAllowedOrigins = List.of("https://default.com", "https://default2.com");
        CorsProperties corsProperties = new CorsProperties(defaultAllowedOrigins, null);

        assertEquals(defaultAllowedOrigins, corsProperties.defaultAllowedOrigins());
    }

    @Test
    void corsProperties_whenExternalAllowedOriginsProvided_returnsExternalAllowedOrigins() {
        List<String> externalAllowedOrigins = List.of("https://external.com", "https://external2.com");
        CorsProperties corsProperties = new CorsProperties(null, externalAllowedOrigins);

        assertEquals(externalAllowedOrigins, corsProperties.externalAllowedOrigins());
    }

    @Test
    void corsProperties_whenNoDefaultAllowedOriginsProvided_returnsEmptyList() {
        CorsProperties corsProperties = new CorsProperties(null, null);

        assertTrue(corsProperties.defaultAllowedOrigins().isEmpty());
    }

    @Test
    void corsProperties_whenNoExternalAllowedOriginsProvided_returnsEmptyList() {
        CorsProperties corsProperties = new CorsProperties(null, null);

        assertTrue(corsProperties.externalAllowedOrigins().isEmpty());
    }
}
