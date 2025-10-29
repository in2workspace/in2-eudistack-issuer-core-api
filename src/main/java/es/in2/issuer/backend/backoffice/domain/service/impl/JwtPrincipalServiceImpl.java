package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.service.JwtPrincipalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtPrincipalServiceImpl implements JwtPrincipalService {

    private final ObjectMapper objectMapper;

    @Override
    public String resolvePrincipal(Jwt jwt) {
        log.info("resolvePrincipal - jwt: {}", jwt.getTokenValue());
        return extractMandateeEmail(jwt).orElse(jwt.getSubject());
    }

    @Override
    public Optional<String> extractMandateeEmail(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaims();

        // Resolve VC from either 'vc' (object) or 'vc_json' (stringified JSON)
        Map<String, Object> vc = resolveVc(claims);
        log.info("vc after resolveVc: {}", vc);

        Map<String, Object> cs = asMap(vc.get("credentialSubject"));
        Map<String, Object> mandate = asMap(cs.get("mandate"));
        Map<String, Object> mandatee = asMap(mandate.get("mandatee"));
        Object email = mandatee.get("email");
        log.info("email: {}", email);

        if (email instanceof String s && isLikelyEmail(s)) {
            return Optional.of(s);
        }

        // Fallback: top-level "email" in the ID token (your sample has it)
        Object topEmail = claims.get("email");
        if (topEmail instanceof String s2 && isLikelyEmail(s2)) {
            return Optional.of(s2);
        }

        return Optional.empty();
    }

    /** Extract VC as a Map from either 'vc' or 'vc_json' (string). */
    private Map<String, Object> resolveVc(Map<String, Object> claims) {
        Object vcObj = claims.get("vc");
        if (vcObj instanceof Map<?, ?>) {
            return asMap(vcObj);
        }

        Object vcJsonObj = claims.get("vc_json");
        if (vcJsonObj instanceof String s && !s.isBlank()) {
            try {
                // Parse the JSON string into a Map
                return objectMapper.readValue(s, new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>(){});
            } catch (Exception e) {
                log.warn("Failed to parse vc_json string", e);
                return Map.of();
            }
        }
        // In case the IDP already places vc_json as an object
        return asMap(vcJsonObj);
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
