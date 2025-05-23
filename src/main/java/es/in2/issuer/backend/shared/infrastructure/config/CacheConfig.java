package es.in2.issuer.backend.shared.infrastructure.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME;
import static es.in2.issuer.backend.shared.domain.util.Constants.VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME;

@Configuration
@RequiredArgsConstructor
public class CacheConfig {

    public long getCacheLifetimeForCredentialOffer() {
        return CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME;
    }

    public long getCacheLifetimeForVerifiableCredential() {
        return VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME;
    }
}
