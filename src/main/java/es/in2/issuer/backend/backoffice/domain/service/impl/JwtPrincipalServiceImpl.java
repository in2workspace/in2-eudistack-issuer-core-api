package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.service.JwtPrincipalService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
public class JwtPrincipalServiceImpl implements JwtPrincipalService {

    @Override
    public String resolvePrincipal(Jwt jwt) {
        log.info("resolvePrincipal - jwt: {}", jwt);
        return extractMandateeEmail(jwt).orElse(jwt.getSubject());
    }

    @Override
    public Optional<String> extractMandateeEmail(Jwt jwt) {
        log.info("extractMandateeEmail");
        Map<String, Object> claims = jwt.getClaims();
        Map<String, Object> vc = asMap(claims.get("vc"));
        Map<String, Object> cs = asMap(vc.get("credentialSubject"));
        Map<String, Object> mandate = asMap(cs.get("mandate"));
        Map<String, Object> mandatee = asMap(mandate.get("mandatee"));
        Object email = mandatee.get("email");
        log.info("email from extractMandateeEmail: {}", email);
        if (email instanceof String s && isLikelyEmail(s)) return Optional.of(s);
        return Optional.empty();
    }

    // --- helpers ---

    /** Defensive map casting to avoid ClassCastException. */
    private Map<String, Object> asMap(Object v) {
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> safe = new HashMap<>();
            m.forEach((k, val) -> { if (k instanceof String s) safe.put(s, val); });
            return safe;
        }
        return Map.of();
    }

    /** Minimal email sanity check; consider replacing with strictier validation. */
    private boolean isLikelyEmail(String s) {
        if (s == null) return false;
        int at = s.indexOf('@');
        return at > 0 && at == s.lastIndexOf('@');
    }
}
