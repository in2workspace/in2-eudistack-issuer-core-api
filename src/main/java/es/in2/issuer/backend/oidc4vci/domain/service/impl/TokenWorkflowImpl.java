package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenWorkflow;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuanceRecordService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
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

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.ACCESS_TOKEN_EXPIRATION_TIME_MINUTES;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.REFRESH_TOKEN_EXPIRATION_TIME_DAYS;
import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenWorkflowImpl implements TokenWorkflow {

    private final CredentialIssuanceRecordService credentialIssuanceRecordService;
    private final CacheStore<String> txCodeByPreAuthorizedCodeCacheStore;
    private final JWTService jwtService;
    private final AppConfig appConfig;

    @Override
    public Mono<TokenResponse> generateTokenResponse(
            String grantType,
            String preAuthorizedCode,
            String txCode) {

        return ensureGrantTypeIsPreAuthorizedCodeAndTxCodeAreCorrect(grantType, preAuthorizedCode, txCode)
                .then(buildTokenResponse(preAuthorizedCode));
    }

    private Mono<TokenResponse> buildTokenResponse(String preAuthorizedCode) {
        Instant issueTime = Instant.now();
        long issueTimeEpochSeconds = issueTime.getEpochSecond();
        long accessTokenExpirationTimeEpochSeconds = generateAccessTokenExpirationTime(issueTime);
        String accessToken = generateAccessToken(preAuthorizedCode, issueTimeEpochSeconds, accessTokenExpirationTimeEpochSeconds);
        String tokenType = "bearer";
        long expiresIn = accessTokenExpirationTimeEpochSeconds - Instant.now().getEpochSecond();
        long refreshTokenExpirationTimeEpochSeconds = generateRefreshTokenExpirationTime(issueTime);
        String refreshToken = generateRefreshToken(issueTimeEpochSeconds, refreshTokenExpirationTimeEpochSeconds);

        // todo guardar els 2 tokens a la cir bbdd
        return Mono.just(TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType(tokenType)
                .expiresIn(expiresIn)
                .refreshToken(refreshToken)
                .build());
    }

    private String generateRefreshToken(long issueTimeEpochSeconds, long expirationTimeEpochSeconds) {
        Payload payload = new Payload(Map.of(
                "iss", appConfig.getIssuerBackendUrl(),
                "iat", issueTimeEpochSeconds,
                "exp", expirationTimeEpochSeconds
        ));
        return jwtService.generateJWT(payload.toString());
    }

    private long generateAccessTokenExpirationTime(Instant issueTime) {
        return issueTime.plus(
                        ACCESS_TOKEN_EXPIRATION_TIME_MINUTES,
                        ChronoUnit.MINUTES)
                .getEpochSecond();
    }

    private long generateRefreshTokenExpirationTime(Instant issueTime) {
        return issueTime.plus(
                        REFRESH_TOKEN_EXPIRATION_TIME_DAYS,
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

    private Mono<Void> ensureGrantTypeIsPreAuthorizedCodeAndTxCodeAreCorrect(String grantType, String preAuthorizedCode, String txCode) {
        if (!GRANT_TYPE.equals(grantType)) {
            return Mono.error(new IllegalArgumentException("Invalid grant type"));
        }

        return txCodeByPreAuthorizedCodeCacheStore
                .get(preAuthorizedCode)
                .onErrorMap(NoSuchElementException.class, ex -> new IllegalArgumentException("Invalid pre-authorized code"))
                .flatMap(cacheTxCode ->
                        cacheTxCode.equals(txCode)
                                ? Mono.empty()
                                : Mono.error(new IllegalArgumentException("Invalid tx code"))
                );
    }
}
