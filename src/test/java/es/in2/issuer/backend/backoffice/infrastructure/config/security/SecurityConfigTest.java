package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import es.in2.issuer.backend.backoffice.domain.service.JwtPrincipalService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

    @Mock private CustomAuthenticationManager customAuthenticationManager;
    @Mock private InternalCORSConfig internalCORSConfig;
    @Mock private PublicCORSConfig publicCORSConfig;
    @Mock private ReactiveJwtDecoder reactiveJwtDecoder; // injected into SecurityConfig as internalJwtDecoder
    @Mock private ProblemAuthenticationEntryPoint entryPoint;
    @Mock private ProblemAccessDeniedHandler deniedHandler;

    @InjectMocks
    private SecurityConfig securityConfig;

    // New mocks for the converter wiring
    @Mock private JwtPrincipalService jwtPrincipalService;

    @Test
    void primaryAuthenticationManager_shouldReturnCustomManager() {
        ReactiveAuthenticationManager manager = securityConfig.primaryAuthenticationManager();
        assertNotNull(manager);
        assertEquals(customAuthenticationManager, manager);
    }

    @Test
    void customAuthenticationWebFilter_shouldCreateFilterWithBearerConverter() {
        var filter = securityConfig.customAuthenticationWebFilter(entryPoint);
        assertNotNull(filter);
    }

    @Test
    void publicFilterChain_shouldBuildWithPublicCorsAndAuthRules() {
        when(publicCORSConfig.publicCorsConfigurationSource()).thenReturn(minimalCorsSource());
        ServerHttpSecurity http = ServerHttpSecurity.http();

        SecurityWebFilterChain chain = securityConfig.publicFilterChain(http, entryPoint, deniedHandler);

        assertNotNull(chain);
        verify(publicCORSConfig, times(1)).publicCorsConfigurationSource();
    }

    @Test
    void backofficeFilterChain_shouldBuildWithInternalCorsAndJwtDecoder() {
        when(internalCORSConfig.defaultCorsConfigurationSource()).thenReturn(minimalCorsSource());
        ServerHttpSecurity http = ServerHttpSecurity.http();

        // Provide a converter bean (could be the real one or a mock). Here we use the real bean factory method:
        Converter<Jwt, Mono<org.springframework.security.authentication.AbstractAuthenticationToken>> converterBean =
                securityConfig.jwtAuthenticationConverter(jwtPrincipalService);

        SecurityWebFilterChain chain = securityConfig.backofficeFilterChain(
                http, entryPoint, deniedHandler, converterBean);

        assertNotNull(chain);
        verify(internalCORSConfig, times(1)).defaultCorsConfigurationSource();
    }

    // --- Tests for JwtToAuthConverter delegating to JwtPrincipalService ---

    private Jwt buildJwt(Map<String, Object> claims, String subject) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .headers(h -> h.put("alg", "none"))
                .claims(c -> c.putAll(claims));
        if (subject != null) builder.subject(subject);
        return builder.build();
    }

    @Test
    void convert_shouldUsePrincipalFromService_whenPresent() {
        // Given a JWT with an email claim (the service decides the principal)
        Map<String, Object> claims = Map.of(
                "vc", Map.of(
                        "credentialSubject", Map.of(
                                "mandate", Map.of(
                                        "mandatee", Map.of("email", "bob@example.com")
                                )
                        )
                )
        );
        Jwt jwt = buildJwt(claims, "ignored-sub");

        // Mock service to return the email as principal
        when(jwtPrincipalService.resolvePrincipal(jwt)).thenReturn("bob@example.com");

        SecurityConfig.JwtToAuthConverter converter =
                new SecurityConfig.JwtToAuthConverter(jwtPrincipalService);

        StepVerifier.create(converter.convert(jwt))
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("bob@example.com", auth.getName());
                })
                .verifyComplete();

        verify(jwtPrincipalService).resolvePrincipal(jwt);
    }

    @Test
    void convert_shouldFallbackPrincipalFromService_whenNoEmail() {
        Jwt jwt = buildJwt(Collections.emptyMap(), "subject-123");

        // Service decides fallback to subject
        when(jwtPrincipalService.resolvePrincipal(jwt)).thenReturn("subject-123");

        SecurityConfig.JwtToAuthConverter converter =
                new SecurityConfig.JwtToAuthConverter(jwtPrincipalService);

        StepVerifier.create(converter.convert(jwt))
                .assertNext(auth -> assertEquals("subject-123", auth.getName()))
                .verifyComplete();

        verify(jwtPrincipalService).resolvePrincipal(jwt);
    }

    // --- helper ---
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
