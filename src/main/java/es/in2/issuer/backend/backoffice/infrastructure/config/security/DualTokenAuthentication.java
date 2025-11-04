package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Objects;

/** Carries the access token (credentials) and an optional id token for identity. */
public final class DualTokenAuthentication extends AbstractAuthenticationToken {

    private final String accessToken;
    @Nullable private final String idToken;

    public DualTokenAuthentication(String accessToken, @Nullable String idToken) {
        super(null);
        this.accessToken = accessToken;
        this.idToken = idToken;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() { return accessToken; }

    @Override
    public Object getPrincipal() {
        // At this stage, the authentication request only carries the raw tokens (access and optional ID token).
        // The user's identity ("principal") is not yet known — this instance represents a pre-authenticated state.
        // Once the tokens are validated by an AuthenticationProvider, a new Authentication object will be created
        // with the proper principal (e.g., a Jwt or UserDetails instance) and marked as authenticated.
        return "N/A";
    }

    public String getAccessToken() {
        return (String) getCredentials();
    }

    @Nullable
    public String getIdToken() { return idToken; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DualTokenAuthentication that)) return false;
        if (!super.equals(o)) return false;
        return Objects.equals(this.accessToken, that.accessToken)
                && Objects.equals(this.idToken, that.idToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), accessToken, idToken);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[authenticated=" + isAuthenticated() + "]";
    }
}

