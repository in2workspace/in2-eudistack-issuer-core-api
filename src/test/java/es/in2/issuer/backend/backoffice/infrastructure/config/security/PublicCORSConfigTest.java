package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.Objects;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PublicCORSConfigTest {

    @Mock
    private AppConfig appConfig;
    @InjectMocks
    private PublicCORSConfig publicCORSConfig;

    @Test
    void publicCorsConfigurationSourceOpen_shouldRegisterExpectedCorsConfigs() {
        UrlBasedCorsConfigurationSource source = publicCORSConfig.publicCorsConfigurationSource();

        // 1. Configuración abierta
        var exchange1 = MockServerWebExchange.from(
                MockServerHttpRequest.get(CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH).build()
        );
        CorsConfiguration openConfig = source.getCorsConfiguration(exchange1);
        assertNotNull(openConfig);
        assertTrue(Objects.requireNonNull(openConfig.getAllowedOriginPatterns()).contains("https://*"));
        assertNotNull(openConfig.getAllowedMethods());
        assertTrue(openConfig.getAllowedMethods().containsAll(List.of("GET", "POST", "OPTIONS")));
    }

    @Test
    void publicCorsConfigurationSourceExternal_shouldRegisterExpectedCorsConfigs() {
        when(appConfig.getExternalCorsAllowedOrigins()).thenReturn(List.of("https://allowed-origin.com"));
        UrlBasedCorsConfigurationSource source = publicCORSConfig.publicCorsConfigurationSource();

        var exchange2 = MockServerWebExchange.from(
                MockServerHttpRequest.get(VCI_ISSUANCES_PATH).build()
        );
        CorsConfiguration externalConfig = source.getCorsConfiguration(exchange2);
        assertNotNull(externalConfig);
        assertNotNull(externalConfig.getAllowedOrigins());
        assertTrue(externalConfig.getAllowedOrigins().contains("https://allowed-origin.com"));
        assertNotNull(externalConfig.getAllowedMethods());
        assertTrue(externalConfig.getAllowedMethods().containsAll(List.of("POST", "OPTIONS")));

    }

    @Test
    void publicCorsConfigurationSourceOid4vci_shouldRegisterExpectedCorsConfigs() {
        when(appConfig.getExternalCorsAllowedOrigins()).thenReturn(List.of("https://allowed-origin.com"));
        UrlBasedCorsConfigurationSource source = publicCORSConfig.publicCorsConfigurationSource();

        var exchange3 = MockServerWebExchange.from(
                MockServerHttpRequest.get(OID4VCI_CREDENTIAL_PATH).build()
        );
        CorsConfiguration oid4vciConfig = source.getCorsConfiguration(exchange3);
        assertNotNull(oid4vciConfig);
        assertNotNull(oid4vciConfig.getAllowedMethods());
        assertTrue(oid4vciConfig.getAllowedMethods().contains("GET"));
        assertTrue(oid4vciConfig.getAllowedMethods().contains("POST"));
    }
}
