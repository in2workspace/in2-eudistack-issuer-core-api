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
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

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

    @Mock
    private ProblemAuthenticationEntryPoint entryPoint;

    @Mock
    private ProblemAccessDeniedHandler deniedHandler;

    @InjectMocks
    private SecurityConfig securityConfig;

    @Test
    void primaryAuthenticationManager_shouldReturnCustomManager() {
        ReactiveAuthenticationManager manager = securityConfig.primaryAuthenticationManager();
        assertNotNull(manager);
        assertEquals(customAuthenticationManager, manager);
    }

    @Test
    void customAuthenticationWebFilter_shouldCreateFilterWithBearerConverter() {
        AuthenticationWebFilter filter = securityConfig.customAuthenticationWebFilter(entryPoint);
        assertNotNull(filter);
    }

    @Test
    void publicFilterChain_shouldBuildWithPublicCorsAndAuthRules() {
        // Given
        when(publicCORSConfig.publicCorsConfigurationSource()).thenReturn(minimalCorsSource());

        ServerHttpSecurity http = ServerHttpSecurity.http();

        // When
        SecurityWebFilterChain chain = securityConfig.publicFilterChain(http, entryPoint, deniedHandler);

        // Then
        assertNotNull(chain);
        verify(publicCORSConfig, times(1)).publicCorsConfigurationSource();
    }

    @Test
    void backofficeFilterChain_shouldBuildWithInternalCorsAndJwtDecoder() {
        // Given
        when(internalCORSConfig.defaultCorsConfigurationSource()).thenReturn(minimalCorsSource());

        ServerHttpSecurity http = ServerHttpSecurity.http();

        // When
        SecurityWebFilterChain chain = securityConfig.backofficeFilterChain(http, entryPoint, deniedHandler);

        // Then
        assertNotNull(chain);
        verify(internalCORSConfig, times(1)).defaultCorsConfigurationSource();
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
