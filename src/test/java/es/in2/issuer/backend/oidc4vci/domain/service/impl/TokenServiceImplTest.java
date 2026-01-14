package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndTxCode;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.RefreshTokenService;
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

import java.time.Instant;
import java.util.NoSuchElementException;

import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
class TokenServiceImplTest {

    private static final String TEST_PRE_AUTHORIZED_CODE = "test-pre-auth-code-123";
    private static final String TEST_TX_CODE = "1234";
    private static final String TEST_CREDENTIAL_PROCEDURE_ID = "credential-procedure-123";
    private static final String TEST_ISSUER_URL = "https://issuer.example.com";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private static final String TEST_REFRESH_TOKEN = "refresh-token-123";
    private static final long TEST_REFRESH_TOKEN_EXPIRES_AT = 1672531200L; // 2023-01-01T00:00:00Z
    private static final String INVALID_GRANT_TYPE = "invalid_grant_type";
    private static final String INVALID_TX_CODE = "wrong-tx-code";

    @Mock
    private CacheStore cacheStore;

    @Mock
    private JWTService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private TokenServiceImpl tokenService;

    private CredentialProcedureIdAndTxCode testCredentialProcedureIdAndTxCode;

    @BeforeEach
    void setUp() {
        testCredentialProcedureIdAndTxCode = new CredentialProcedureIdAndTxCode(
                TEST_CREDENTIAL_PROCEDURE_ID,
                TEST_TX_CODE
        );
    }

    @Test
    void generateTokenResponse_WhenValidInputs_ShouldReturnTokenResponse() {
        // Arrange
        when(cacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.just(testCredentialProcedureIdAndTxCode));
        when(appConfig.getIssuerBackendUrl()).thenReturn(TEST_ISSUER_URL);
        when(jwtService.generateJWT(anyString())).thenReturn(TEST_ACCESS_TOKEN);
        when(refreshTokenService.generateRefreshTokenExpirationTime(any(Instant.class)))
                .thenReturn(TEST_REFRESH_TOKEN_EXPIRES_AT);
        when(refreshTokenService.generateRefreshToken()).thenReturn(TEST_REFRESH_TOKEN);
        when(cacheStore.add(anyString(), any()))
                .thenReturn(Mono.just(TEST_PRE_AUTHORIZED_CODE));

        // Act & Assert
        StepVerifier.create(tokenService.generateTokenResponse(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE))
                .assertNext(tokenResponse -> {
                    assertThat(tokenResponse).isNotNull();
                    assertThat(tokenResponse.accessToken()).isEqualTo(TEST_ACCESS_TOKEN);
                    assertThat(tokenResponse.tokenType()).isEqualTo("bearer");
                    assertThat(tokenResponse.expiresIn()).isGreaterThan(0);
                })
                .verifyComplete();

        // Verify interactions
        verify(cacheStore, times(2)).get(TEST_PRE_AUTHORIZED_CODE);
        verify(jwtService).generateJWT(anyString());
        verify(refreshTokenService).generateRefreshTokenExpirationTime(any(Instant.class));
        verify(refreshTokenService).generateRefreshToken();
        verify(cacheStore).add(eq(TEST_PRE_AUTHORIZED_CODE), any(CredentialProcedureIdAndRefreshToken.class));
    }

    @Test
    void generateTokenResponse_WhenInvalidGrantType_ShouldReturnError() {
        // Act & Assert
        StepVerifier.create(tokenService.generateTokenResponse(INVALID_GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE))
                .expectErrorMatches(throwable ->
                    throwable instanceof IllegalArgumentException &&
                    throwable.getMessage().equals("Invalid grant type: " + INVALID_GRANT_TYPE))
                .verify();

        verifyNoInteractions(cacheStore);
        verifyNoInteractions(jwtService);
        verifyNoInteractions(refreshTokenService);
    }

    @Test
    void generateTokenResponse_WhenInvalidPreAuthorizedCode_ShouldReturnError() {
        // Arrange
        when(cacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.error(new NoSuchElementException("Pre-authorized code not found")));

        // Act & Assert
        StepVerifier.create(tokenService.generateTokenResponse(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE))
                .expectErrorMatches(throwable ->
                    throwable instanceof IllegalArgumentException &&
                    throwable.getMessage().equals("Invalid pre-authorized code"))
                .verify();

        verify(cacheStore).get(TEST_PRE_AUTHORIZED_CODE);
    }

    @Test
    void generateTokenResponse_WhenInvalidTxCode_ShouldReturnError() {
        // Arrange
        when(cacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.just(testCredentialProcedureIdAndTxCode));

        // Act & Assert
        StepVerifier.create(tokenService.generateTokenResponse(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, INVALID_TX_CODE))
                .expectErrorMatches(throwable ->
                    throwable instanceof IllegalArgumentException &&
                    throwable.getMessage().equals("Invalid tx code"))
                .verify();

        verify(cacheStore).get(TEST_PRE_AUTHORIZED_CODE);
    }

    @Test
    void generateTokenResponse_WhenCacheStoreThrowsException_ShouldReturnError() {
        // Arrange
        RuntimeException cacheException = new RuntimeException("Cache store error");
        when(cacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.error(cacheException));

        // Act & Assert
        StepVerifier.create(tokenService.generateTokenResponse(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE))
                .expectErrorMatches(throwable ->
                    throwable instanceof IllegalArgumentException &&
                    throwable.getMessage().equals("Invalid pre-authorized code"))
                .verify();

        verify(cacheStore).get(TEST_PRE_AUTHORIZED_CODE);
    }

    @Test
    void generateTokenResponse_WhenRefreshTokenCacheFails_ShouldReturnError() {
        // Arrange
        when(cacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.just(testCredentialProcedureIdAndTxCode));
        when(appConfig.getIssuerBackendUrl()).thenReturn(TEST_ISSUER_URL);
        when(jwtService.generateJWT(anyString())).thenReturn(TEST_ACCESS_TOKEN);
        when(refreshTokenService.generateRefreshTokenExpirationTime(any(Instant.class)))
                .thenReturn(TEST_REFRESH_TOKEN_EXPIRES_AT);
        when(refreshTokenService.generateRefreshToken()).thenReturn(TEST_REFRESH_TOKEN);

        RuntimeException refreshTokenCacheException = new RuntimeException("Refresh token cache error");
        when(cacheStore.add(eq(TEST_PRE_AUTHORIZED_CODE), any(CredentialProcedureIdAndRefreshToken.class)))
                .thenReturn(Mono.error(refreshTokenCacheException));

        // Act & Assert
        StepVerifier.create(tokenService.generateTokenResponse(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE))
                .expectError(RuntimeException.class)
                .verify();

        verify(cacheStore).add(eq(TEST_PRE_AUTHORIZED_CODE), any(CredentialProcedureIdAndRefreshToken.class));
    }

    @Test
    void generateTokenResponse_WhenJWTServiceFails_ShouldReturnError() {
        // Arrange
        when(cacheStore.get(TEST_PRE_AUTHORIZED_CODE))
                .thenReturn(Mono.just(testCredentialProcedureIdAndTxCode));
        when(appConfig.getIssuerBackendUrl()).thenReturn(TEST_ISSUER_URL);

        RuntimeException jwtException = new RuntimeException("JWT generation failed");
        when(jwtService.generateJWT(anyString())).thenThrow(jwtException);

        // Act & Assert
        StepVerifier.create(tokenService.generateTokenResponse(GRANT_TYPE, TEST_PRE_AUTHORIZED_CODE, TEST_TX_CODE))
                .expectError(RuntimeException.class)
                .verify();

        verify(jwtService).generateJWT(anyString());
    }
}
