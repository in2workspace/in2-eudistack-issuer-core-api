package es.in2.issuer.backend.backoffice.domain.service.impl;


import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.service.JwtPrincipalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtPrincipalServiceImplTest {

    private JwtPrincipalService service;

    @BeforeEach
    void setUp() {
        service = new JwtPrincipalServiceImpl(new ObjectMapper());
    }

    // --- helpers ---

    private Jwt buildJwt(Map<String, Object> claims, String subject) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .headers(h -> h.put("alg", "none"))
                .claims(c -> c.putAll(claims))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600));
        if (subject != null) builder.subject(subject);
        return builder.build();
    }

    private Map<String, Object> nestedEmail(String email) {
        return Map.of(
                "vc", Map.of(
                        "credentialSubject", Map.of(
                                "mandate", Map.of(
                                        "mandatee", Map.of("email", email)
                                )
                        )
                )
        );
    }

    // --- extractMandateeEmail ---

    @Test
    void extractMandateeEmail_returnsEmail_whenValidNestedClaim() {
        Jwt jwt = buildJwt(nestedEmail("alice@example.com"), "ignored");
        var opt = service.extractMandateeEmail(jwt);
        assertTrue(opt.isPresent());
        assertEquals("alice@example.com", opt.get());
    }

    @Test
    void extractMandateeEmail_returnsEmpty_whenEmailIsNonString() {
        Map<String, Object> claims = Map.of(
                "vc", Map.of(
                        "credentialSubject", Map.of(
                                "mandate", Map.of(
                                        "mandatee", Map.of("email", 1234) // not a String
                                )
                        )
                )
        );
        Jwt jwt = buildJwt(claims, "ignored");
        assertTrue(service.extractMandateeEmail(jwt).isEmpty());
    }

    @Test
    void extractMandateeEmail_returnsEmpty_whenInvalidEmailFormats() {
        // No '@'
        Jwt jwtNoAt = buildJwt(nestedEmail("invalid-email"), "ignored");
        assertTrue(service.extractMandateeEmail(jwtNoAt).isEmpty());

        // Leading '@'
        Jwt jwtLeadingAt = buildJwt(nestedEmail("@example.com"), "ignored");
        assertTrue(service.extractMandateeEmail(jwtLeadingAt).isEmpty());

        // Multiple '@'
        Jwt jwtDoubleAt = buildJwt(nestedEmail("a@@b.com"), "ignored");
        assertTrue(service.extractMandateeEmail(jwtDoubleAt).isEmpty());
    }

    @Test
    void extractMandateeEmail_returnsEmpty_whenStructureMissingOrWrongTypes() {
        // Completely missing chain
        Jwt jwtMissing = buildJwt(Collections.emptyMap(), "ignored");
        assertTrue(service.extractMandateeEmail(jwtMissing).isEmpty());

        // Intermediate nodes not being maps (defensive asMap should handle it)
        Map<String, Object> broken = Map.of(
                "vc", "not-a-map"
        );
        Jwt jwtBroken = buildJwt(broken, "ignored");
        assertTrue(service.extractMandateeEmail(jwtBroken).isEmpty());
    }

    // --- resolvePrincipal ---

    @Test
    void resolvePrincipal_prefersEmail_overSubject() {
        Jwt jwt = buildJwt(nestedEmail("bob@example.com"), "subject-xyz");
        String principal = service.resolvePrincipal(jwt);
        assertEquals("bob@example.com", principal);
    }

    @Test
    void resolvePrincipal_fallsBackToSubject_whenEmailMissing() {
        Jwt jwt = buildJwt(Collections.emptyMap(), "fallback-subject");
        String principal = service.resolvePrincipal(jwt);
        assertEquals("fallback-subject", principal);
    }
}

