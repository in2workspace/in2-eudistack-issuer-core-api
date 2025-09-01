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
        // No podem inspeccionar fàcilment el matcher/converter interns, però el simple fet de construir-lo
        // sense excepcions valida que s’ha cablejat el manager i el failure handler.
    }

    @Test
    void publicFilterChain_shouldBuildWithPublicCorsAndAuthRules() {
        // Given
        when(publicCORSConfig.publicCorsConfigurationSource()).thenReturn(minimalCorsSource());

        // ServerHttpSecurity factory estàtica per WebFlux
        ServerHttpSecurity http = ServerHttpSecurity.http();

        // When
        SecurityWebFilterChain chain = securityConfig.publicFilterChain(http, entryPoint, deniedHandler);

        // Then
        assertNotNull(chain);
        verify(publicCORSConfig, times(1)).publicCorsConfigurationSource();
        // S’afegeix també el customAuthenticationWebFilter com a filtre d’auth
        // i s’estableixen entryPoint/deniedHandler a exceptionHandling sense excepcions.
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
        // El jwtDecoder s’injecta al config del resource server; si hi hagués cap problema, petaria al build().
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
