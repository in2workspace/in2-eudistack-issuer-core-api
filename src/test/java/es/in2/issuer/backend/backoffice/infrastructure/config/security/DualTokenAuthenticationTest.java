package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DualTokenAuthenticationTest {

    @Test
    void constructor_setsFieldsAndDefaultAuthenticationState() {
        String accessToken = "access-123";
        String idToken = "id-456";

        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication auth = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication(accessToken, idToken);

        // Access token is exposed via getCredentials()
        assertEquals(accessToken, auth.getCredentials());
        assertEquals(idToken, auth.getIdToken());
        assertEquals("N/A", auth.getPrincipal());
        assertFalse(auth.isAuthenticated(), "New DualTokenAuthentication should be unauthenticated by default");

        assertNotNull(auth.getAuthorities());
        assertTrue(auth.getAuthorities().isEmpty(), "Authorities should be empty when constructed");
    }

    @Test
    void constructor_withNullIdToken_allowsNullValue() {
        String accessToken = "access-only";

        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication auth = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication(accessToken, null);

        assertEquals(accessToken, auth.getCredentials());
        assertNull(auth.getIdToken());
        assertFalse(auth.isAuthenticated());
    }

    @Test
    void canChangeAuthenticatedFlag() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication auth = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("a", null);
        assertFalse(auth.isAuthenticated());

        auth.setAuthenticated(true);
        assertTrue(auth.isAuthenticated());

        auth.setAuthenticated(false);
        assertFalse(auth.isAuthenticated());
    }

    // ---------- Overrides coverage below ----------

    @Test
    void getCredentials_and_getPrincipal_areOverridden() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication auth = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("access-xyz", "id-xyz");
        assertEquals("access-xyz", auth.getCredentials());
        assertEquals("N/A", auth.getPrincipal());
    }

    @Test
    void getIdToken_and_getCredentials_returnValues() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication withBoth = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("A", "I");
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication withOnlyAccess = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("A", null);

        assertEquals("I", withBoth.getIdToken());
        assertEquals("A", withBoth.getCredentials());

        assertNull(withOnlyAccess.getIdToken());
        assertEquals("A", withOnlyAccess.getCredentials());
    }

    @Test
    void equals_reflexive_symmetric_transitive_and_hashCode_consistent_forSameTokens() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a1 = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a2 = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a3 = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");

        // Reflexive
        assertEquals(a1, a1);
        // Symmetric
        assertEquals(a1, a2);
        assertEquals(a2, a1);
        // Transitive
        assertEquals(a2, a3);
        assertEquals(a1, a3);

        // hashCode consistency
        assertEquals(a1.hashCode(), a2.hashCode());
        assertEquals(a2.hashCode(), a3.hashCode());
    }

    @Test
    void equals_returnsFalse_whenComparedWithNullOrDifferentType() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");
        assertNotEquals(null, a);
        assertNotEquals("not-an-auth-object", a);
    }

    @Test
    void equals_returnsFalse_whenAccessTokenDiffers() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc1", "id");
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication b = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc2", "id");
        assertNotEquals(a, b);
    }

    @Test
    void equals_returnsFalse_whenIdTokenDiffersIncludingNullVsNonNull() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication nonNullId = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication differentId = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "other");
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication nullId = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", null);

        assertNotEquals(nonNullId, differentId);
        assertNotEquals(nonNullId, nullId);

        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication nullId2 = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", null);
        assertEquals(nullId, nullId2, "Both idToken null and same accessToken -> equal");
    }

    @Test
    void equals_accountsForSuperFields_authenticatedFlagDiffers() {
        // Note: AbstractAuthenticationToken.equals() considers authentication state among other things.
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication b = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");

        // Same initial state => equal
        assertEquals(a, b);

        // Change authenticated on one => NOT equal
        a.setAuthenticated(true);
        assertNotEquals(a, b);

        // Align again => equal
        b.setAuthenticated(true);
        assertEquals(a, b);
    }

    @Test
    void equals_accountsForSuperFields_detailsDiffer() {
        // Note: AbstractAuthenticationToken.equals() includes details in equality.
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication b = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");

        // Baseline equal
        assertEquals(a, b);

        // Set details only in one instance => not equal
        a.setDetails("some-details");
        assertNotEquals(a, b);

        // Align details => equal again
        b.setDetails("some-details");
        assertEquals(a, b);
    }

    @Test
    void hashCode_changesWhenTokensOrSuperStateChange() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id");
        int base = a.hashCode();

        // Change tokens by creating a new instance with different values
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication differentTokens = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc2", "id");
        assertNotEquals(base, differentTokens.hashCode());

        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication differentId = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", "id2");
        assertNotEquals(base, differentId.hashCode());

        // Change super state (authenticated) should also affect hashCode
        a.setAuthenticated(true);
        int afterAuth = a.hashCode();
        assertNotEquals(base, afterAuth);

        // Change details should affect hashCode too
        a.setDetails("d1");
        int afterDetails = a.hashCode();
        assertNotEquals(afterAuth, afterDetails);
    }

    @Test
    void toString_includesClassNameAndAuthenticatedFlag() {
        es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication a = new es.in2.issuer.backend.backoffice.infrastructure.config.security.DualTokenAuthentication("acc", null);
        String s1 = a.toString();
        assertTrue(s1.contains("DualTokenAuthentication"), "toString should include simple class name");
        assertTrue(s1.contains("authenticated=false"), "toString should reflect unauthenticated state");

        a.setAuthenticated(true);
        String s2 = a.toString();
        assertTrue(s2.contains("authenticated=true"), "toString should reflect authenticated state");
    }
}
