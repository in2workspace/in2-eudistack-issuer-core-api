package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import es.in2.issuer.backend.shared.domain.service.JWTService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.STATUS_LIST_BASE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

    @Mock private CustomAuthenticationManager customAuthenticationManager;
    @Mock private InternalCORSConfig internalCORSConfig;
    @Mock private PublicCORSConfig publicCORSConfig;
    @Mock private ReactiveJwtDecoder internalJwtDecoder;
    @Mock private ProblemAuthenticationEntryPoint entryPoint;
    @Mock private ProblemAccessDeniedHandler deniedHandler;
    @Mock private JWTService jwtService;

    private WebFilterChainProxy securityProxy;

    @BeforeEach
    void setUp() {
        SecurityConfig securityConfig = new SecurityConfig(
                customAuthenticationManager,
                internalCORSConfig,
                publicCORSConfig,
                internalJwtDecoder
        );

        when(internalCORSConfig.defaultCorsConfigurationSource()).thenReturn(minimalCorsSource());

        Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtConverter =
                securityConfig.jwtAuthenticationConverter(jwtService);

        SecurityWebFilterChain chain = securityConfig.internalFilterChain(
                ServerHttpSecurity.http(),
                entryPoint,
                deniedHandler,
                jwtConverter
        );

        securityProxy = new WebFilterChainProxy(chain);
    }


    @Test
    void statusList_post_shouldReturn401_whenNoAuth() {
        doAnswer(inv -> {
            var exchange = inv.getArgument(0, org.springframework.web.server.ServerWebExchange.class);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }).when(entryPoint).commence(any(), any());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post(STATUS_LIST_BASE).build()
        );

        securityProxy.filter(exchange, ex -> {
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return ex.getResponse().setComplete();
        }).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }


    @Test
    void statusList_post_shouldReturn200_whenAuthenticated() {
        Jwt jwt = buildJwt(Map.of("scope", "any"), "subject-123");

        when(jwtService.resolvePrincipal(any(Jwt.class))).thenReturn("subject-123");
        when(internalJwtDecoder.decode("good-token")).thenReturn(Mono.just(jwt));

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post(STATUS_LIST_BASE)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                        .build()
        );

        securityProxy.filter(exchange, ex -> {
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return ex.getResponse().setComplete();
        }).block();

        assertEquals(HttpStatus.OK, exchange.getResponse().getStatusCode());
        verify(internalJwtDecoder).decode("good-token");
        verify(jwtService).resolvePrincipal(any(Jwt.class));
    }

    @Test
    void statusList_get_shouldBePermitAll() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get(STATUS_LIST_BASE).build()
        );

        securityProxy.filter(exchange, ex -> {
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return ex.getResponse().setComplete();
        }).block();

        assertEquals(HttpStatus.OK, exchange.getResponse().getStatusCode());
    }

    private UrlBasedCorsConfigurationSource minimalCorsSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOriginPattern("*");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private Jwt buildJwt(Map<String, Object> claims, String subject) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .headers(h -> h.put("alg", "none"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .claims(c -> c.putAll(claims));

        if (subject != null) {
            builder.subject(subject);
        }
        return builder.build();
    }
}
