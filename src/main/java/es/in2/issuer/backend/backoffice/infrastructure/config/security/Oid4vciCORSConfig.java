package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;

@Configuration
@RequiredArgsConstructor

public class Oid4vciCORSConfig {
    /**
     * Default CORS configuration source.
     */
    @Bean
    public UrlBasedCorsConfigurationSource oid4vciCorsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(1800L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(OID4VCI_CREDENTIAL_OFFER_PATH, configuration);
        source.registerCorsConfiguration(OAUTH_TOKEN_PATH, configuration);
        source.registerCorsConfiguration(OID4VCI_CREDENTIAL_PATH, configuration);
        return source;
    }
}
