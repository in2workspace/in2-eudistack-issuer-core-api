package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
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
import java.util.concurrent.TimeUnit;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.ACCESS_TOKEN_EXPIRATION_TIME_DAYS;
import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final CacheStore<String> txCodeByPreAuthorizedCodeCacheStore;
    private final CacheStore<String> nonceCacheStore;
    private final JWTService jwtService;
    private final AppConfig appConfig;
    // TODO: Token Workflow

    @Override
    public Mono<TokenResponse> generateTokenResponse(
            String grantType,
            String preAuthorizedCode,
            String txCode) {

        // TODO join two ensure functions
        return ensureGrantTypeIsPreAuthorizedCode(grantType)
                .then(Mono.defer(() -> ensurePreAuthorizedCodeAndTxCodeAreCorrect(preAuthorizedCode, txCode)))
                .then(Mono.defer(this::generateAndSaveNonce)
                        .map(nonce -> {
                            // TODO extract to a function
                            Instant issueTime = Instant.now();
                            long issueTimeEpochSeconds = issueTime.getEpochSecond();
                            long expirationTimeEpochSeconds = generateAccessTokenExpirationTime(issueTime);
                            String accessToken = generateAccessToken(preAuthorizedCode, issueTimeEpochSeconds, expirationTimeEpochSeconds);
                            String tokenType = "bearer";
                            long expiresIn = expirationTimeEpochSeconds - Instant.now().getEpochSecond();

                            // TODO: Generate Refresh token -> Un token amb un claim de refresh token i validesa de 30 dies.
                            // todo guardar els 2 tokens a la cir bbdd
                            return TokenResponse.builder()
                                    .accessToken(accessToken)
                                    .tokenType(tokenType)
                                    .expiresIn(expiresIn)
                                    .build();
                        }));
    }

    // TODO: delete
    private Mono<String> generateAndSaveNonce() {
        return generateCustomNonce()
                .flatMap(nonce ->
                        nonceCacheStore.add(nonce, nonce));
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

    private Mono<Void> ensurePreAuthorizedCodeAndTxCodeAreCorrect(String preAuthorizedCode, String txCode) {
        return txCodeByPreAuthorizedCodeCacheStore
                .get(preAuthorizedCode)
                .onErrorMap(NoSuchElementException.class, ex -> new IllegalArgumentException("Invalid pre-authorized code"))
                .flatMap(cacheTxCode ->
                        cacheTxCode.equals(txCode)
                                ? Mono.empty()
                                : Mono.error(new IllegalArgumentException("Invalid tx code"))
                );
    }


    private Mono<Void> ensureGrantTypeIsPreAuthorizedCode(String grantType) {
        return GRANT_TYPE.equals(grantType)
                ? Mono.empty()
                : Mono.error(new IllegalArgumentException("Invalid grant type"));
    }
}
