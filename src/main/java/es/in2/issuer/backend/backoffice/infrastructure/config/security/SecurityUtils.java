package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
@Slf4j
public final class SecurityUtils {

    private SecurityUtils() {}

    /** Returns Mono<String> with the current principal ("emails" or "systems" from Authentication.getName()) */
    public static Mono<String> getCurrentPrincipal() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .map(Authentication::getName)
                .filter(name -> name != null && !name.isBlank());
    }

    /** Returns Mono<String> with the organizationIdentifier (or empty Mono if missing). */
    public static Mono<String> currentOrgId(ObjectMapper objectMapper) {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .flatMap(auth -> extractOrgId(auth.getTokenAttributes(), objectMapper));
    }

    /** Returns Mono<String> that errors if orgId is missing (useful for domain rules). */
    public static Mono<String> requireOrgId(ObjectMapper objectMapper) {
        return currentOrgId(objectMapper)
                .switchIfEmpty(Mono.error(new IllegalStateException("organizationIdentifier missing in token")));
    }

    private static Mono<String> extractOrgId(Map<String, Object> attrs, ObjectMapper objectMapper) {
        Object mandator = attrs.get("mandator");
        if (mandator == null) {
            return Mono.empty();
        }

        if (mandator instanceof Map<?, ?> mandatorMap) {
            Object orgId = mandatorMap.get("organizationIdentifier");
            if (orgId instanceof String s && !s.isBlank()) {
                return Mono.just(s);
            }
            return Mono.empty();
        }

        if (mandator instanceof String mandatorJson) {
            try {
                Map<?, ?> mandatorMap = objectMapper.readValue(mandatorJson, Map.class);
                Object orgId = mandatorMap.get("organizationIdentifier");
                if (orgId instanceof String s && !s.isBlank()) {
                    return Mono.just(s);
                }
                return Mono.empty();
            } catch (Exception e) {
                return Mono.error(e);
            }
        }

        return Mono.empty();
    }
}
