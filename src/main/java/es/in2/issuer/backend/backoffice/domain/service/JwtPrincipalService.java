package es.in2.issuer.backend.backoffice.domain.service;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Optional;

public interface JwtPrincipalService {
    /** Returns email if present or falls back to sub. */
    String resolvePrincipal(Jwt jwt);

    /** Extract mandatee email if present. */
    Optional<String> extractMandateeEmail(Jwt jwt);
}
