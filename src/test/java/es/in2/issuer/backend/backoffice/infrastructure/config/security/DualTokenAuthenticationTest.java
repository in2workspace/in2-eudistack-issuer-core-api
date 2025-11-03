package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DualTokenAuthenticationTest {

    @Test
    void constructor_setsFieldsAndDefaultAuthenticationState() {
        String accessToken = "access-123";
        String idToken = "id-456";

        DualTokenAuthentication auth = new DualTokenAuthentication(accessToken, idToken);

        assertEquals(accessToken, auth.getAccessToken());
        assertEquals(idToken, auth.getIdToken());
        assertEquals(accessToken, auth.getCredentials());
        assertEquals("N/A", auth.getPrincipal());
        assertFalse(auth.isAuthenticated(), "New DualTokenAuthentication should be unauthenticated by default");

        assertNotNull(auth.getAuthorities());
        assertTrue(auth.getAuthorities().isEmpty(), "Authorities should be empty when constructed with null");
    }


    @Test
    void constructor_withNullIdToken_allowsNullValue() {
        String accessToken = "access-only";

        DualTokenAuthentication auth = new DualTokenAuthentication(accessToken, null);

        assertEquals(accessToken, auth.getAccessToken());
        assertNull(auth.getIdToken());
        assertEquals(accessToken, auth.getCredentials());
        assertFalse(auth.isAuthenticated());
    }

    @Test
    void canChangeAuthenticatedFlag() {
        DualTokenAuthentication auth = new DualTokenAuthentication("a", null);
        assertFalse(auth.isAuthenticated());

        auth.setAuthenticated(true);
        assertTrue(auth.isAuthenticated());

        auth.setAuthenticated(false);
        assertFalse(auth.isAuthenticated());
    }
}
