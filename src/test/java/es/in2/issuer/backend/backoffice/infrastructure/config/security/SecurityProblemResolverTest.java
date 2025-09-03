package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import es.in2.issuer.backend.backoffice.infrastructure.config.security.SecurityProblemResolver.ProblemSpec;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.*;

class SecurityProblemResolverTest {

    private final SecurityProblemResolver resolver = new SecurityProblemResolver();

    @Test
    void resolves_BadCredentials_to_Unauthorized_InvalidToken() {
        ProblemSpec spec = resolver.resolve(new BadCredentialsException("bad token"), true);

        assertNotNull(spec);
        assertEquals("Invalid token", spec.title());
        assertEquals(HttpStatus.UNAUTHORIZED, spec.status());
        assertEquals("Invalid token", spec.fallbackDetail());
        assertNotNull(spec.type()); // no assumim el codi concret, però ha d'existir
    }

    @Test
    void resolves_UsernameNotFound_to_Unauthorized_UserNotFound() {
        ProblemSpec spec = resolver.resolve(new UsernameNotFoundException("no user"), true);

        assertNotNull(spec);
        assertEquals("User not found", spec.title());
        assertEquals(HttpStatus.UNAUTHORIZED, spec.status());
        assertEquals("Authentication failed", spec.fallbackDetail());
        assertNotNull(spec.type());
    }

    @Test
    void resolves_Disabled_to_Unauthorized_UserDisabled() {
        ProblemSpec spec = resolver.resolve(new DisabledException("disabled"), true);

        assertNotNull(spec);
        assertEquals("User disabled", spec.title());
        assertEquals(HttpStatus.UNAUTHORIZED, spec.status());
        assertEquals("Authentication failed", spec.fallbackDetail());
    }

    @Test
    void resolves_InsufficientAuthentication_to_Unauthorized_WithAdditionalAuthRequired() {
        ProblemSpec spec = resolver.resolve(new InsufficientAuthenticationException("more auth"), true);

        assertNotNull(spec);
        assertEquals("Insufficient authentication", spec.title());
        assertEquals(HttpStatus.UNAUTHORIZED, spec.status());
        assertEquals("Additional authentication required", spec.fallbackDetail());
    }

    @Test
    void resolves_CredentialsExpired_to_Unauthorized() {
        ProblemSpec spec = resolver.resolve(new CredentialsExpiredException("expired"), true);

        assertNotNull(spec);
        assertEquals("Credentials expired", spec.title());
        assertEquals(HttpStatus.UNAUTHORIZED, spec.status());
        assertEquals("Authentication failed", spec.fallbackDetail());
    }

    @Test
    void resolves_AccessDenied_to_Forbidden() {
        ProblemSpec spec = resolver.resolve(new AccessDeniedException("no access"), false);

        assertNotNull(spec);
        assertEquals("Forbidden", spec.title());
        assertEquals(HttpStatus.FORBIDDEN, spec.status());
        assertEquals("Access denied", spec.fallbackDetail());
        assertNotNull(spec.type());
    }

    @Test
    void fallsBackToDefaultAuthSpec_whenNoMapping_andAuthPhaseTrue() {
        // Excepció desconeguda en fase d'autenticació -> DEFAULT_AUTH_SPEC
        ProblemSpec spec = resolver.resolve(new IllegalStateException("???"), true);

        assertNotNull(spec);
        assertEquals("Unauthorized", spec.title());
        assertEquals(HttpStatus.UNAUTHORIZED, spec.status());
        assertEquals("Authentication failed", spec.fallbackDetail());
        assertNotNull(spec.type());
    }

    @Test
    void fallsBackToDefaultAccessSpec_whenNoMapping_andAuthPhaseFalse() {
        // Excepció desconeguda en fase d’autorització -> DEFAULT_ACCESS_SPEC
        ProblemSpec spec = resolver.resolve(new IllegalStateException("???"), false);

        assertNotNull(spec);
        assertEquals("Forbidden", spec.title());
        assertEquals(HttpStatus.FORBIDDEN, spec.status());
        assertEquals("Access denied", spec.fallbackDetail());
        assertNotNull(spec.type());
    }

    @Test
    void resolvesBySuperclass_whenSubclassMatchesMappedType() {
        // Definim una subclasse de BadCredentialsException per assegurar-nos que fa "walk" per la superclasse
        class MyBadCreds extends BadCredentialsException {
            MyBadCreds(String msg) { super(msg); }
        }

        ProblemSpec spec = resolver.resolve(new MyBadCreds("custom bad creds"), true);

        assertNotNull(spec);
        assertEquals("Invalid token", spec.title());            // mateix mapping que BadCredentialsException
        assertEquals(HttpStatus.UNAUTHORIZED, spec.status());
        assertEquals("Invalid token", spec.fallbackDetail());
        assertNotNull(spec.type());
    }
}
