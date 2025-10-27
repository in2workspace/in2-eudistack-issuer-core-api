package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
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

        SecurityWebFilterChain chain = securityConfig.backofficeFilterChain(http, entryPoint, deniedHandler);

        assertNotNull(chain);
        verify(internalCORSConfig, times(1)).defaultCorsConfigurationSource();
    }

    // --- Tests for JwtToAuthConverter and its private helpers ---

    private Jwt buildJwt(Map<String, Object> claims, String subject) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .headers(h -> h.put("alg", "none"))
                .claims(c -> c.putAll(claims));
        if (subject != null) builder.subject(subject);
        return builder.build();
    }

    @Test
    void convert_shouldUseMandateeEmailAsPrincipal_whenPresent() {
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
        SecurityConfig.JwtToAuthConverter converter = new SecurityConfig.JwtToAuthConverter();

        StepVerifier.create(converter.convert(jwt))
                .assertNext(auth -> {
                    assertTrue(auth instanceof JwtAuthenticationToken);
                    assertEquals("bob@example.com", auth.getName());
                })
                .verifyComplete();
    }

    @Test
    void convert_shouldFallbackToSubject_whenNoMandateeEmail() {
        Jwt jwt = buildJwt(Collections.emptyMap(), "subject-123");
        SecurityConfig.JwtToAuthConverter converter = new SecurityConfig.JwtToAuthConverter();

        StepVerifier.create(converter.convert(jwt))
                .assertNext(auth -> assertEquals("subject-123", auth.getName()))
                .verifyComplete();
    }

    @Test
    void resolvePrincipal_prefersEmail_overSubject() throws Exception {
        Method m = SecurityConfig.JwtToAuthConverter.class
                .getDeclaredMethod("resolvePrincipal", Jwt.class);
        m.setAccessible(true);

        Map<String, Object> claims = Map.of(
                "vc", Map.of(
                        "credentialSubject", Map.of(
                                "mandate", Map.of(
                                        "mandatee", Map.of("email", "alice@example.com")
                                )
                        )
                )
        );
        Jwt jwt = buildJwt(claims, "subject-xyz");
        String principal = (String) m.invoke(null, jwt);
        assertEquals("alice@example.com", principal);
    }

    @Test
    void resolvePrincipal_fallsBackToSubject_whenEmailMissing() throws Exception {
        Method m = SecurityConfig.JwtToAuthConverter.class
                .getDeclaredMethod("resolvePrincipal", Jwt.class);
        m.setAccessible(true);

        Jwt jwt = buildJwt(Collections.emptyMap(), "fallback-subject");
        String principal = (String) m.invoke(null, jwt);
        assertEquals("fallback-subject", principal);
    }

    @Test
    void asMap_returnsMap_whenInputIsMap_elseEmptyMap() throws Exception {
        Method m = SecurityConfig.JwtToAuthConverter.class
                .getDeclaredMethod("asMap", Object.class);
        m.setAccessible(true);

        Map<String, Object> input = Map.of("key", "value");
        @SuppressWarnings("unchecked")
        Map<String, Object> result1 = (Map<String, Object>) m.invoke(null, input);
        assertEquals(input, result1);

        @SuppressWarnings("unchecked")
        Map<String, Object> result2 = (Map<String, Object>) m.invoke(null, "not a map");
        assertTrue(result2.isEmpty());
    }

    @Test
    void extractMandateeEmail_returnsEmail_whenValidNestedClaim() throws Exception {
        Method m = SecurityConfig.JwtToAuthConverter.class
                .getDeclaredMethod("extractMandateeEmail", Jwt.class);
        m.setAccessible(true);

        Map<String, Object> claims = Map.of(
                "vc", Map.of(
                        "credentialSubject", Map.of(
                                "mandate", Map.of(
                                        "mandatee", Map.of("email", "charlie@example.com")
                                )
                        )
                )
        );
        Jwt jwt = buildJwt(claims, "subject-ignored");
        String email = (String) m.invoke(null, jwt);
        assertEquals("charlie@example.com", email);
    }

    @Test
    void extractMandateeEmail_returnsNull_whenInvalidOrMissing() throws Exception {
        Method m = SecurityConfig.JwtToAuthConverter.class
                .getDeclaredMethod("extractMandateeEmail", Jwt.class);
        m.setAccessible(true);

        // Invalid email (no '@')
        Map<String, Object> invalid = Map.of(
                "vc", Map.of(
                        "credentialSubject", Map.of(
                                "mandate", Map.of(
                                        "mandatee", Map.of("email", "not-an-email")
                                )
                        )
                )
        );
        Jwt jwtInvalid = buildJwt(invalid, "ignored");
        assertNull(m.invoke(null, jwtInvalid));

        // Missing structure
        Jwt jwtMissing = buildJwt(Collections.emptyMap(), "ignored");
        assertNull(m.invoke(null, jwtMissing));
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
