package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndTxCode;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.RefreshTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.NoSuchElementException;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.ACCESS_TOKEN_EXPIRATION_TIME_DAYS;
import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private static final String TOKEN_TYPE = "bearer";

    private final CacheStore<CredentialProcedureIdAndTxCode> txCodeCacheStore;
    private final CacheStore<CredentialProcedureIdAndRefreshToken> refreshTokenCacheStore;
    private final JWTService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AppConfig appConfig;

    @Override
    public Mono<TokenResponse> generateTokenResponse(String grantType, String preAuthorizedCode, String txCode) {
        log.debug("Generating token response for pre-authorized code: {}", preAuthorizedCode);

        return validateGrantType(grantType)
                .then(validatePreAuthorizedCodeAndTxCode(preAuthorizedCode, txCode))
                .then(generateTokens(preAuthorizedCode))
                .doOnSuccess(response -> log.debug("Token response generated successfully"))
                .doOnError(error -> log.error("Error generating token response for code {}: {}", preAuthorizedCode, error.getMessage()));
    }

    private Mono<Void> validateGrantType(String grantType) {
        return GRANT_TYPE.equals(grantType)
                ? Mono.empty()
                : Mono.error(new IllegalArgumentException("Invalid grant type: " + grantType));
    }

    private Mono<Void> validatePreAuthorizedCodeAndTxCode(String preAuthorizedCode, String txCode) {
        return txCodeCacheStore
                .get(preAuthorizedCode)
                .doOnError(error -> log.error("Failed to retrieve tx code data for pre-authorized code: {}", preAuthorizedCode))
                .onErrorMap(NoSuchElementException.class, ex -> new IllegalArgumentException("Invalid pre-authorized code"))
                .flatMap(credentialProcedureIdAndTxCode -> {
                    if (credentialProcedureIdAndTxCode.TxCode().equals(txCode)) {
                        return Mono.empty();
                    } else {
                        log.error("Invalid tx code provided for pre-authorized code: {}", preAuthorizedCode);
                        return Mono.error(new IllegalArgumentException("Invalid tx code"));
                    }
                });
    }

    private Mono<TokenResponse> generateTokens(String preAuthorizedCode) {
        Instant issueTime = Instant.now();
        long accessTokenExpirationTime = generateAccessTokenExpirationTime(issueTime);
        String accessToken = generateAccessToken(preAuthorizedCode, issueTime.getEpochSecond(), accessTokenExpirationTime);

        return getCredentialProcedureId(preAuthorizedCode)
                .flatMap(credentialProcedureId -> createRefreshTokenEntry(credentialProcedureId, issueTime, preAuthorizedCode))
                .then(Mono.fromCallable(() -> buildTokenResponse(accessToken, accessTokenExpirationTime)));
    }

    private long generateAccessTokenExpirationTime(Instant issueTime) {
        return issueTime.plus(
                        ACCESS_TOKEN_EXPIRATION_TIME_DAYS,
                        ChronoUnit.DAYS)
                .getEpochSecond();
    }

    private String generateAccessToken(String preAuthorizedCode, long issueTimeEpochSeconds, long expirationTimeEpochSeconds) {
        Payload payload = new Payload(Map.of(
                "iss", appConfig.getIssuerBackendUrl(),
                "iat", issueTimeEpochSeconds,
                "exp", expirationTimeEpochSeconds,
                "jti", preAuthorizedCode
        ));
        return jwtService.generateJWT(payload.toString());
    }

    private Mono<String> getCredentialProcedureId(String preAuthorizedCode) {
        return txCodeCacheStore
                .get(preAuthorizedCode)
                .map(CredentialProcedureIdAndTxCode::credentialProcedureId)
                .doOnError(error -> log.warn("Failed to retrieve credential procedure ID for PreAuthorizedCode: {}", preAuthorizedCode));
    }

    private Mono<Void> createRefreshTokenEntry(String credentialProcedureId, Instant issueTime, String preAuthorizedCode) {
        long refreshTokenExpiresAt = refreshTokenService.generateRefreshTokenExpirationTime(issueTime);
        String refreshToken = refreshTokenService.generateRefreshToken();

        CredentialProcedureIdAndRefreshToken credentialProcedureIdAndRefreshToken =
                CredentialProcedureIdAndRefreshToken.builder()
                        .credentialProcedureId(credentialProcedureId)
                        .refreshTokenJti(refreshToken)
                        .refreshTokenExpiresAt(refreshTokenExpiresAt)
                        .build();

        return refreshTokenCacheStore.add(preAuthorizedCode, credentialProcedureIdAndRefreshToken).then();
    }

    private TokenResponse buildTokenResponse(String accessToken, long accessTokenExpirationTime) {
        long expiresIn = accessTokenExpirationTime - Instant.now().getEpochSecond();
        return TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType(TOKEN_TYPE)
                .expiresIn(expiresIn)
                .build();
    }
}
