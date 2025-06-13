package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.model.dto.VerifiableCredentialJWT;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

import static es.in2.issuer.backend.shared.domain.util.Constants.PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {

    private final CacheConfig cacheConfig;

    @Bean
    public CacheStore<String> cacheStoreDefault() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<String> cacheStoreForTransactionCode() {
        return new CacheStore<>(72, TimeUnit.HOURS);
    }

    @Bean
    public CacheStore<String> cacheStoreForCTransactionCode() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<VerifiableCredentialJWT> cacheStoreForVerifiableCredentialJwt() {
        return new CacheStore<>(cacheConfig.getCacheLifetimeForVerifiableCredential(), TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<CredentialOfferData> cacheStoreForCredentialOffer() {
        return new CacheStore<>(cacheConfig.getCacheLifetimeForCredentialOffer(), TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<String> txCodeByPreAuthorizedCodeCacheStore() {
        return new CacheStore<>(PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<String> nonceCacheStore() {
        return new CacheStore<>(PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<String> issuanceMetadataCacheStore() {
        return new CacheStore<>(PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<String> cacheStoreForIssuanceMetadata() {
        return new CacheStore<>(45, TimeUnit.DAYS);
    }
}
