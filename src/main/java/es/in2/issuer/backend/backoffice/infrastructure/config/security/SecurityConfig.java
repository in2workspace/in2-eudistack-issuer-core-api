package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationManager customAuthenticationManager;
    private final InternalCORSConfig internalCORSConfig;
    private final PublicCORSConfig publicCORSConfig;
    private final ReactiveJwtDecoder internalJwtDecoder;

    @Bean
    @Primary
    public ReactiveAuthenticationManager primaryAuthenticationManager() {
        return customAuthenticationManager;
    }

    @Bean
    public AuthenticationWebFilter customAuthenticationWebFilter(ProblemAuthenticationEntryPoint entryPoint) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(customAuthenticationManager);
        // Set the path for which the filter will be applied
        log.debug("customAuthenticationWebFilter - inside");

        authenticationWebFilter.setRequiresAuthenticationMatcher(
                ServerWebExchangeMatchers.pathMatchers(
                        VCI_ISSUANCES_PATH,
                        OAUTH_TOKEN_PATH,
                        OID4VCI_CREDENTIAL_PATH,
                        OID4VCI_DEFERRED_CREDENTIAL_PATH)
        );
        // Configure the Bearer token authentication converter
        ServerBearerTokenAuthenticationConverter bearerConverter = new ServerBearerTokenAuthenticationConverter() {
            @Override
            public Mono<Authentication> convert(ServerWebExchange exchange) {
                log.debug("CustomAuthenticationWebFilter triggered -> [{} {}]",
                        exchange.getRequest().getMethod(),
                        exchange.getRequest().getPath());
                return super.convert(exchange);
            }
        };
        authenticationWebFilter.setServerAuthenticationConverter(bearerConverter);
        authenticationWebFilter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(entryPoint));
        return authenticationWebFilter;
    }

    @Bean
    @Order(1)
    public SecurityWebFilterChain publicFilterChain(
            ServerHttpSecurity http,
            ProblemAuthenticationEntryPoint entryPoint,
            ProblemAccessDeniedHandler deniedH
    ) {
        log.debug("publicFilterChain - inside");

        http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(
                        CORS_OID4VCI_PATH,
                        VCI_PATH,
                        WELL_KNOWN_PATH,
                        OAUTH_PATH
                ))
                .cors(cors -> cors.configurationSource(publicCORSConfig.publicCorsConfigurationSource()))
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(HttpMethod.GET,
                                CORS_CREDENTIAL_OFFER_PATH,
                                CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH,
                                AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH
                        ).permitAll()
                        .pathMatchers(HttpMethod.POST, OAUTH_TOKEN_PATH).permitAll()
                        .pathMatchers(HttpMethod.POST,
                                VCI_ISSUANCES_PATH,
                                OID4VCI_CREDENTIAL_PATH,
                                OID4VCI_DEFERRED_CREDENTIAL_PATH
                        ).authenticated()
                        .anyExchange().denyAll()
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .addFilterAt(customAuthenticationWebFilter(entryPoint), SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedH)
                );
        log.debug("publicFilterChain - build");
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityWebFilterChain backofficeFilterChain(
            ServerHttpSecurity http,
            ProblemAuthenticationEntryPoint entryPoint,
            ProblemAccessDeniedHandler deniedH) {

        log.debug("backofficeFilterChain - inside");

        http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(
                        BACKOFFICE_PATH,
                        ACTUATOR_PATH,
                        SPRINGDOC_PATH
                ))
                .cors(cors -> cors.configurationSource(internalCORSConfig.defaultCorsConfigurationSource()))
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(HttpMethod.GET,
                                ACTUATOR_PATH,
                                SPRINGDOC_PATH
                        ).permitAll()
                        .pathMatchers(HttpMethod.GET, BACKOFFICE_STATUS_CREDENTIALS).permitAll()
                        .pathMatchers(HttpMethod.GET, BACKOFFICE_PATH).authenticated()
                        .pathMatchers(HttpMethod.POST, BACKOFFICE_PATH ).authenticated()
                        .pathMatchers(HttpMethod.PUT, BACKOFFICE_PATH).authenticated()
                        .pathMatchers(HttpMethod.DELETE, BACKOFFICE_PATH).authenticated()
                        .anyExchange().denyAll()
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationEntryPoint(entryPoint)
                        .jwt(jwt -> jwt.jwtDecoder(internalJwtDecoder)))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedH)
                );
        log.debug("backofficeFilterChain - build");
        return http.build();
    }

}