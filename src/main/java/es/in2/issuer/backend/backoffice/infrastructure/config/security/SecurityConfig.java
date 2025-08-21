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
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationManager customAuthenticationManager;
    private final ReactiveJwtDecoder internalJwtDecoder;
    private final InternalCORSConfig internalCORSConfig;
    private final ExternalServicesCORSConfig externalServicesCORSConfig;
    private final PublicCORSConfig publicCORSConfig;
    private final Oid4vciCORSConfig oid4VciCORSConfig;
    private final Oidc4vciAuthenticationManager oidc4vciAuthenticationManager;

    @Bean
    @Primary
    public ReactiveAuthenticationManager primaryAuthenticationManager() {
        return customAuthenticationManager;
    }

    @Bean
    public AuthenticationWebFilter customAuthenticationWebFilter(ProblemAuthenticationEntryPoint entryPoint) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(customAuthenticationManager);
        // Set the path for which the filter will be applied
        authenticationWebFilter.setRequiresAuthenticationMatcher(
                ServerWebExchangeMatchers.pathMatchers(VCI_ISSUANCES_PATH)
        );
        // Configure the Bearer token authentication converter
        ServerBearerTokenAuthenticationConverter bearerConverter = new ServerBearerTokenAuthenticationConverter();
        authenticationWebFilter.setServerAuthenticationConverter(bearerConverter);

        ServerAuthenticationEntryPointFailureHandler ServerAuthenticationEntryPointFailureHandler = new ServerAuthenticationEntryPointFailureHandler(entryPoint);
        authenticationWebFilter.setAuthenticationFailureHandler(ServerAuthenticationEntryPointFailureHandler);
        return authenticationWebFilter;
    }

    @Bean
    @Order(1)
    public SecurityWebFilterChain publicFilterChain(ServerHttpSecurity http) {
        http
                .securityMatcher(
                        ServerWebExchangeMatchers.matchers(
                                ServerWebExchangeMatchers.pathMatchers(
                                        HttpMethod.GET,
                                        SWAGGER_UI_PATH,
                                        SWAGGER_RESOURCES_PATH,
                                        SWAGGER_API_DOCS_PATH,
                                        SWAGGER_SPRING_UI_PATH,
                                        SWAGGER_WEBJARS_PATH,
                                        HEALTH_PATH,
                                        CORS_CREDENTIAL_OFFER_PATH,
                                        CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH,
                                        AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH,
                                        PROMETHEUS_PATH,
                                        STATUS_CREDENTIALS
                                ),
                                ServerWebExchangeMatchers.pathMatchers(
                                        HttpMethod.POST,
                                        OAUTH_TOKEN_PATH,
                                        DEFERRED_CREDENTIALS
                                )
                        )
                )
                .cors(cors -> cors.configurationSource(publicCORSConfig.publicCorsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(
                                HttpMethod.GET,
                                SWAGGER_UI_PATH,
                                SWAGGER_RESOURCES_PATH,
                                SWAGGER_API_DOCS_PATH,
                                SWAGGER_SPRING_UI_PATH,
                                SWAGGER_WEBJARS_PATH,
                                HEALTH_PATH,
                                CORS_CREDENTIAL_OFFER_PATH,
                                CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH,
                                AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH,
                                PROMETHEUS_PATH,
                                STATUS_CREDENTIALS
                        ).permitAll()
                        .pathMatchers(
                                HttpMethod.POST,
                                OAUTH_TOKEN_PATH,
                                DEFERRED_CREDENTIALS
                        ).permitAll()
                        .anyExchange().authenticated()
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable);

        return http.build();
    }

    // External filter chain for external endpoints
    @Bean
    @Order(2)
    public SecurityWebFilterChain externalFilterChain(ServerHttpSecurity http,
                                                      ProblemAuthenticationEntryPoint entryPoint) {
        http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, VCI_ISSUANCES_PATH))
                .cors(cors -> cors.configurationSource(externalServicesCORSConfig.externalCorsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().authenticated()
                )
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .addFilterAt(customAuthenticationWebFilter(entryPoint), SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }

    //todo entry point?
    @Bean
    @Order(3)
    public SecurityWebFilterChain oid4vciFilterChain(ServerHttpSecurity http, ProblemAuthenticationEntryPoint entryPoint) {
        http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(CORS_OID4VCI_PATH))
                .cors(cors -> cors.configurationSource(oid4VciCORSConfig.oid4vciCorsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(OAUTH_TOKEN_PATH, OID4VCI_CREDENTIAL_OFFER_PATH).permitAll()
                        .anyExchange().authenticated()
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint))
                .addFilterAt(oid4vciBearerAuthenticationFilter(entryPoint), SecurityWebFiltersOrder.AUTHENTICATION);
        return http.build();
    }

    // Internal security configuration for internal endpoints
    @Bean
    @Order(4)
    public SecurityWebFilterChain internalFilterChain(ServerHttpSecurity http,
                                                      ProblemAuthenticationEntryPoint entryPoint) {
        http
                .securityMatcher(ServerWebExchangeMatchers.anyExchange())
                .cors(cors -> internalCORSConfig.defaultCorsConfigurationSource())
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().authenticated()
                )
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint))
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer
                                .jwt(jwtSpec -> jwtSpec
                                        .jwtDecoder(internalJwtDecoder))

                );
        return http.build();
    }

    private AuthenticationWebFilter oid4vciBearerAuthenticationFilter(ProblemAuthenticationEntryPoint entryPoint) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(oidc4vciAuthenticationManager);

        // Set the path for which the filter will be applied
        ServerWebExchangeMatcher excludedPaths = ServerWebExchangeMatchers.pathMatchers(OAUTH_TOKEN_PATH, OID4VCI_CREDENTIAL_OFFER_PATH);
        authenticationWebFilter.setRequiresAuthenticationMatcher(
                new NegatedServerWebExchangeMatcher(excludedPaths)
        );
        // Configure the Bearer token authentication converter
        ServerBearerTokenAuthenticationConverter bearerConverter = new ServerBearerTokenAuthenticationConverter();
        authenticationWebFilter.setServerAuthenticationConverter(bearerConverter);

        ServerAuthenticationEntryPointFailureHandler ServerAuthenticationEntryPointFailureHandler = new ServerAuthenticationEntryPointFailureHandler(entryPoint);
        authenticationWebFilter.setAuthenticationFailureHandler(ServerAuthenticationEntryPointFailureHandler);
        return authenticationWebFilter;
    }

}