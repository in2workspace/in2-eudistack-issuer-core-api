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

    // ---------- Overrides coverage below ----------

    @Test
    void getCredentials_and_getPrincipal_areOverridden() {
        DualTokenAuthentication auth = new DualTokenAuthentication("access-xyz", "id-xyz");
        assertEquals("access-xyz", auth.getCredentials());
        assertEquals("N/A", auth.getPrincipal());
    }

    @Test
    void getAccessToken_and_getIdToken_returnValues() {
        DualTokenAuthentication withBoth = new DualTokenAuthentication("A", "I");
        DualTokenAuthentication withOnlyAccess = new DualTokenAuthentication("A", null);

        assertEquals("A", withBoth.getAccessToken());
        assertEquals("I", withBoth.getIdToken());

        assertEquals("A", withOnlyAccess.getAccessToken());
        assertNull(withOnlyAccess.getIdToken());
    }

    @Test
    void equals_reflexive_symmetric_transitive_and_hashCode_consistent_forSameTokens() {
        DualTokenAuthentication a1 = new DualTokenAuthentication("acc", "id");
        DualTokenAuthentication a2 = new DualTokenAuthentication("acc", "id");
        DualTokenAuthentication a3 = new DualTokenAuthentication("acc", "id");

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
        DualTokenAuthentication a = new DualTokenAuthentication("acc", "id");
        assertNotEquals(a, null);
        assertNotEquals(a, "not-an-auth-object");
    }

    @Test
    void equals_returnsFalse_whenAccessTokenDiffers() {
        DualTokenAuthentication a = new DualTokenAuthentication("acc1", "id");
        DualTokenAuthentication b = new DualTokenAuthentication("acc2", "id");
        assertNotEquals(a, b);
    }

    @Test
    void equals_returnsFalse_whenIdTokenDiffersIncludingNullVsNonNull() {
        DualTokenAuthentication nonNullId = new DualTokenAuthentication("acc", "id");
        DualTokenAuthentication differentId = new DualTokenAuthentication("acc", "other");
        DualTokenAuthentication nullId = new DualTokenAuthentication("acc", null);

        assertNotEquals(nonNullId, differentId);
        assertNotEquals(nonNullId, nullId);

        DualTokenAuthentication nullId2 = new DualTokenAuthentication("acc", null);
        assertEquals(nullId, nullId2, "Both idToken null and same accessToken -> equal");
    }

    @Test
    void equals_accountsForSuperFields_authenticatedFlagDiffers() {
        // Note: AbstractAuthenticationToken.equals() considers authentication state among other things.
        DualTokenAuthentication a = new DualTokenAuthentication("acc", "id");
        DualTokenAuthentication b = new DualTokenAuthentication("acc", "id");

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
        DualTokenAuthentication a = new DualTokenAuthentication("acc", "id");
        DualTokenAuthentication b = new DualTokenAuthentication("acc", "id");

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
        DualTokenAuthentication a = new DualTokenAuthentication("acc", "id");
        int base = a.hashCode();

        // Change tokens by creating a new instance with different values
        DualTokenAuthentication differentTokens = new DualTokenAuthentication("acc2", "id");
        assertNotEquals(base, differentTokens.hashCode());

        DualTokenAuthentication differentId = new DualTokenAuthentication("acc", "id2");
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
        DualTokenAuthentication a = new DualTokenAuthentication("acc", null);
        String s1 = a.toString();
        assertTrue(s1.contains("DualTokenAuthentication"), "toString should include simple class name");
        assertTrue(s1.contains("authenticated=false"), "toString should reflect unauthenticated state");

        a.setAuthenticated(true);
        String s2 = a.toString();
        assertTrue(s2.contains("authenticated=true"), "toString should reflect authenticated state");
    }
}
