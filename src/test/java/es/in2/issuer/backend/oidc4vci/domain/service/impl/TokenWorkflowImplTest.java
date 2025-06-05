package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.NoSuchElementException;

import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenWorkflowImplTest {
    @Mock
    private CacheStore<String> txCodeByPreAuthorizedCodeCacheStore;

    @Mock
    private CacheStore<String> nonceCacheStore;

    @Mock
    private JWTService jwtService;

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private TokenWorkflowImpl tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenWorkflowImpl(
                txCodeByPreAuthorizedCodeCacheStore,
                nonceCacheStore,
                jwtService,
                appConfig
        );
    }

    @Test
    void generateTokenResponse_ShouldReturnValidTokenResponse() {
        String preAuthorizedCode = "validPreAuthCode";
        String txCode = "validTxCode";
        String accessToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";

        when(txCodeByPreAuthorizedCodeCacheStore.get(anyString()))
                .thenReturn(Mono.just(txCode));
        when(nonceCacheStore.add(anyString(), anyString()))
                .thenReturn(Mono.just("mockedNonce"));
        when(jwtService.generateJWT(any()))
                .thenReturn(accessToken);
        when(appConfig.getIssuerBackendUrl())
                .thenReturn("mockedIssuerDomain");

        Mono<TokenResponse> result = tokenService.generateTokenResponse(GRANT_TYPE, preAuthorizedCode, txCode);

        StepVerifier.create(result)
                .assertNext(tokenResponse -> {
                    assertThat(tokenResponse).isNotNull();
                    assertThat(tokenResponse.accessToken()).isEqualTo(accessToken);
                    assertThat(tokenResponse.tokenType()).isEqualTo("bearer");
                    assertThat(tokenResponse.nonce()).isNotNull();
                    assertThat(tokenResponse.expiresIn()).isGreaterThan(0);
                    assertThat(tokenResponse.nonceExpiresIn()).isGreaterThan(0);
                })
                .verifyComplete();
    }

    @Test
    void generateTokenResponse_ShouldReturnError_WhenGrantTypeIsInvalid() {
        String grantType = "invalidGrantType";
        String preAuthorizedCode = "validPreAuthCode";
        String txCode = "validTxCode";

        Mono<TokenResponse> result = tokenService.generateTokenResponse(grantType, preAuthorizedCode, txCode);

        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void generateTokenResponse_ShouldReturnError_WhenPreAuthorizedCodeIsInvalid() {
        String preAuthorizedCode = "invalidPreAuthCode";
        String txCode = "validTxCode";

        when(txCodeByPreAuthorizedCodeCacheStore.get(preAuthorizedCode))
                .thenReturn(Mono.error(new NoSuchElementException("Value is not present.")));

        Mono<TokenResponse> result = tokenService.generateTokenResponse(GRANT_TYPE, preAuthorizedCode, txCode);

        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void generateTokenResponse_ShouldReturnError_WhenTxCodeIsInvalid() {
        String preAuthorizedCode = "validPreAuthCode";
        String txCode = "invalidTxCode";

        String cacheTxCode = "2f30e394-f29d-4fcf-a47b-274a4659f3e6";
        when(txCodeByPreAuthorizedCodeCacheStore.get(preAuthorizedCode))
                .thenReturn(Mono.just(cacheTxCode));

        Mono<TokenResponse> result = tokenService.generateTokenResponse(GRANT_TYPE, preAuthorizedCode, txCode);

        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();
    }
}