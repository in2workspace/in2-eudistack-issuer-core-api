package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialIdAndTxCode;
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
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceImplTest {
    @Mock
    private CacheStore<CredentialIdAndTxCode> credentialIdAndTxCodeByPreAuthorizedCodeCacheStore;

    @Mock
    private CacheStore<String> nonceCacheStore;

    @Mock
    private JWTService jwtService;

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private TokenServiceImpl tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenServiceImpl(
                credentialIdAndTxCodeByPreAuthorizedCodeCacheStore,
                nonceCacheStore,
                jwtService,
                appConfig
        );
    }

    @Test
    void generateTokenResponse_ShouldReturnValidTokenResponse() {
        String preAuthorizedCode = "validPreAuthCode";
        String txCode = "validTxCode";
        CredentialIdAndTxCode credential = new CredentialIdAndTxCode(UUID.fromString(
                "2f30e394-f29d-4fcf-a47b-274a4659f3e6"),
                txCode);
        String accessToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";

        when(credentialIdAndTxCodeByPreAuthorizedCodeCacheStore.get(anyString()))
                .thenReturn(Mono.just(credential));
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
                    assertThat(tokenResponse.expiresIn()).isGreaterThan(0);
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

        when(credentialIdAndTxCodeByPreAuthorizedCodeCacheStore.get(preAuthorizedCode))
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

        CredentialIdAndTxCode credential = new CredentialIdAndTxCode(UUID.fromString(
                "2f30e394-f29d-4fcf-a47b-274a4659f3e6"),
                "validTxCode");
        when(credentialIdAndTxCodeByPreAuthorizedCodeCacheStore.get(preAuthorizedCode))
                .thenReturn(Mono.just(credential));

        Mono<TokenResponse> result = tokenService.generateTokenResponse(GRANT_TYPE, preAuthorizedCode, txCode);

        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();
    }
}