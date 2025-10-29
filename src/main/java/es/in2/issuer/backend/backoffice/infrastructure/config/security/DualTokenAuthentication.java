package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;

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

    public String getAccessToken() { return accessToken; }

    @Nullable
    public String getIdToken() { return idToken; }
}

