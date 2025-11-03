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
    public Object getPrincipal() { return "N/A"; } // principal will be resolved post-validation

    public String getAccessToken() {
        return (String) getCredentials();
    }

    @Nullable
    public String getIdToken() { return idToken; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DualTokenAuthentication that)) return false;
        if (!super.equals(o)) return false; // keep AbstractAuthenticationToken's equality parts
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

