package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

    @Mock
    private CustomAuthenticationManager customAuthenticationManager;
    @Mock
    private InternalCORSConfig internalCORSConfig;
    @Mock
    private PublicCORSConfig publicCORSConfig;
    @Mock
    private ReactiveJwtDecoder reactiveJwtDecoder;

    @InjectMocks
    private SecurityConfig securityConfig;

    @Test
    void primaryAuthenticationManager_shouldReturnCustomManager() {
        ReactiveAuthenticationManager manager = securityConfig.primaryAuthenticationManager();
        assertNotNull(manager);
        assertEquals(customAuthenticationManager, manager);
    }

    @Test
    void customAuthenticationWebFilter_shouldBeConfigured() {
        var filter = securityConfig.customAuthenticationWebFilter();
        assertNotNull(filter);
    }

    @Test
    void publicFilterChain_shouldBuildWithoutErrors() {
        when(publicCORSConfig.publicCorsConfigurationSource()).thenReturn(minimalCorsSource());
        SecurityWebFilterChain chain = securityConfig.publicFilterChain(ServerHttpSecurity.http());
        assertNotNull(chain);
    }

    @Test
    void backofficeFilterChain_shouldBuildWithoutErrors() {
        when(internalCORSConfig.defaultCorsConfigurationSource()).thenReturn(minimalCorsSource());
        SecurityWebFilterChain chain = securityConfig.backofficeFilterChain(ServerHttpSecurity.http());
        assertNotNull(chain);
    }



    private UrlBasedCorsConfigurationSource minimalCorsSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
