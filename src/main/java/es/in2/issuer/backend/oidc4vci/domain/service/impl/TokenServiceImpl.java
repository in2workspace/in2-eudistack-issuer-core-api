package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndTxCode;
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

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.ACCESS_TOKEN_EXPIRATION_TIME_DAYS;
import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final CacheStore<CredentialProcedureIdAndTxCode> credentialProcedureIdAndTxCodeByPreAuthorizedCodeCacheStore;
    private final CacheStore<CredentialProcedureIdAndRefreshToken> credentialProcedureIdAndRefreshTokenCacheStore;
    private final JWTService jwtService;
    private final AppConfig appConfig;

    @Override
    public Mono<TokenResponse> generateTokenResponse(
            String grantType,
            String preAuthorizedCode,
            String txCode) {

        return validateGrantTypeIsPreAuthorizedCode(grantType)
                .then(Mono.defer(() -> validatePreAuthorizedCodeAndTxCodeAreCorrect(preAuthorizedCode, txCode)))
                .then(Mono.defer(() -> {

                    Instant issueTime = Instant.now();
                    long accessTokenExpirationTimeEpochSeconds = generateAccessTokenExpirationTime(issueTime);
                    String accessToken = generateAccessToken(
                            preAuthorizedCode,
                            issueTime.getEpochSecond(),
                            accessTokenExpirationTimeEpochSeconds);

                    return getCredentialProcedureId(preAuthorizedCode)
                            .flatMap(credentialProcedureId -> {
                                long refreshTokenExpiresAt = generateRefreshTokenExpirationTime(issueTime);
                                String refreshToken = generateRefreshToken();

                                return buildCredentialProcedureIdAndRefreshToken(
                                        credentialProcedureId,
                                        refreshToken,
                                        refreshTokenExpiresAt
                                )
                                        .flatMap(obj ->
                                                saveCredentialProcedureIdAndRefreshTokenCacheStoreByPreAuthorizedCode(
                                                        preAuthorizedCode,
                                                        obj
                                                )
                                        )
                                        .then(Mono.fromSupplier(() -> {
                                            String tokenType = "bearer";
                                            long expiresIn = accessTokenExpirationTimeEpochSeconds - Instant.now().getEpochSecond();
                                            return TokenResponse.builder()
                                                    .accessToken(accessToken)
                                                    .tokenType(tokenType)
                                                    .expiresIn(expiresIn)
                                                    .build();
                                        }));
                            });
                }));
    }

    private Mono<String> getCredentialProcedureId(String preAuthorizedCode) {
        return credentialProcedureIdAndTxCodeByPreAuthorizedCodeCacheStore
                .get(preAuthorizedCode)
                .map(CredentialProcedureIdAndTxCode::credentialProcedureId);
    }

    private Mono<String> saveCredentialProcedureIdAndRefreshTokenCacheStoreByPreAuthorizedCode(
            String preAuthorizedCode,
            CredentialProcedureIdAndRefreshToken credentialProcedureIdAndRefreshToken) {
        return credentialProcedureIdAndRefreshTokenCacheStore
                .add(preAuthorizedCode, credentialProcedureIdAndRefreshToken);
    }

    private Mono<CredentialProcedureIdAndRefreshToken> buildCredentialProcedureIdAndRefreshToken(
            String credentialProcedureId,
            String refreshToken,
            long refreshTokenExpiresAt) {
        return Mono.just(
                CredentialProcedureIdAndRefreshToken.builder()
                        .credentialProcedureId(credentialProcedureId)
                        .refreshTokenJti(refreshToken)
                        .refreshTokenExpiresAt(refreshTokenExpiresAt)
                        .build()
        );
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

    private Mono<Void> validatePreAuthorizedCodeAndTxCodeAreCorrect(String preAuthorizedCode, String txCode) {
        return credentialProcedureIdAndTxCodeByPreAuthorizedCodeCacheStore
                .get(preAuthorizedCode)
                .onErrorMap(NoSuchElementException.class, ex -> new IllegalArgumentException("Invalid pre-authorized code"))
                .flatMap(credentialProcedureIdAndTxCode ->
                        credentialProcedureIdAndTxCode.TxCode().equals(txCode)
                                ? Mono.empty()
                                : Mono.error(new IllegalArgumentException("Invalid tx code"))
                );
    }


    private Mono<Void> validateGrantTypeIsPreAuthorizedCode(String grantType) {
        return GRANT_TYPE.equals(grantType)
                ? Mono.empty()
                : Mono.error(new IllegalArgumentException("Invalid grant type"));
    }
}
