package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.ProofValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SUPPORTED_PROOF_ALG;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SUPPORTED_PROOF_TYP;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProofValidationServiceImpl implements ProofValidationService {

    private final JWTService jwtService;


    @Override
    public Mono<Boolean> isProofValid(String jwtProof, Set<String> allowedAlgs, String expectedAudience) {
        return Mono.just(jwtProof)
                .doOnNext(jwt -> log.debug("Starting validation for JWT: {}", jwt))
                .flatMap(jwt -> parseAndValidateJwt(jwt, expectedAudience))
                .doOnNext(jws -> log.debug("JWT parsed successfully"))
                .flatMap(signedJWT ->
                        jwtService.validateJwtSignatureReactive(signedJWT)
                                .doOnSuccess(isSignatureValid -> log.debug("Signature validation result: {}", isSignatureValid))
                                .map(isSignatureValid -> Boolean.TRUE.equals(isSignatureValid) ? signedJWT : null)
                )
                .doOnNext(signedJWT -> {
                    if (signedJWT == null) log.debug("JWT signature validation failed");
                    else log.debug("JWT signature validated, checking nonce...");
                })
                .map(Objects::nonNull)
                // TODO: Check nonce when implemented
                .doOnSuccess(result -> log.debug("Final validation result: {}", result))
                .onErrorMap(e -> new ProofValidationException("Error during JWT validation"));
    }

    private Mono<SignedJWT> parseAndValidateJwt(String jwtProof, String expectedAudience) {
        return Mono.fromCallable(() -> {
            SignedJWT signedJWT = SignedJWT.parse(jwtProof);
            validateJwtHeader(signedJWT);
            validatePayload(signedJWT, expectedAudience);
            return signedJWT;
        });
    }

    private void validateJwtHeader(SignedJWT signedJWT) {
        Map<String, Object> headerParams = signedJWT.getHeader().toJSONObject();

        Object algObj = headerParams.get("alg");
        Object typObj = headerParams.get("typ");
        if (algObj == null || typObj == null) {
            throw new IllegalArgumentException("Invalid JWT header: alg or typ missing");
        }

        String alg = algObj.toString();
        String typ = typObj.toString();

        boolean hasJwk = isHasJwk(typ, alg, headerParams);

        if (hasJwk) {
            Object jwkObj = headerParams.get("jwk");
            if (jwkObj instanceof Map<?, ?> jwkMap && (jwkMap.containsKey("d") || jwkMap.containsKey("p") ||
                        jwkMap.containsKey("q") || jwkMap.containsKey("dp") ||
                        jwkMap.containsKey("dq") || jwkMap.containsKey("qi"))) {
                    throw new IllegalArgumentException("Invalid JWT header: JWK must not contain private key material");
            }
        }
    }

    private boolean isHasJwk(String typ, String alg, Map<String, Object> headerParams) {
        if (!SUPPORTED_PROOF_TYP.equals(typ)) {
            throw new IllegalArgumentException("Invalid JWT header: unsupported typ");
        }

        if ("none".equalsIgnoreCase(alg) || alg.toUpperCase().startsWith("HS")) {
            throw new IllegalArgumentException("Invalid JWT header: alg must be asymmetric and not 'none'");
        }

        return isHasJwk(alg, headerParams);
    }

    private boolean isHasJwk(String alg, Map<String, Object> headerParams) {
        if (!SUPPORTED_PROOF_ALG.equals(alg)) {
            throw new IllegalArgumentException("Invalid JWT header: alg not supported");
        }

        boolean hasKid = headerParams.containsKey("kid");
        boolean hasJwk = headerParams.containsKey("jwk");
        boolean hasX5c = headerParams.containsKey("x5c");

        if ((hasKid ? 1 : 0) + (hasJwk ? 1 : 0) + (hasX5c ? 1 : 0) != 1) {
            throw new IllegalArgumentException("Invalid JWT header: exactly one of kid, jwk or x5c must be present");
        }
        return hasJwk;
    }


    private void validatePayload(SignedJWT signedJWT, String expectedAudience) {
        var payload = signedJWT.getPayload().toJSONObject();

        Object audObj = payload.get("aud");
        if (audObj == null || audObj.toString().isBlank()) {
            throw new IllegalArgumentException("Invalid JWT payload: aud is missing");
        }

        boolean audMatches = (audObj instanceof String s && s.equals(expectedAudience)) || (audObj instanceof java.util.List<?> list && list.stream().anyMatch(a -> expectedAudience.equals(String.valueOf(a))));

        if (!audMatches) {
            throw new IllegalArgumentException(
                    "Invalid JWT payload: aud must be '" + expectedAudience + "' but was " + audObj
            );
        }

        Object iatObj = payload.get("iat");
        if (iatObj == null) {
            throw new IllegalArgumentException("Invalid JWT payload: iat is missing");
        }

        long iatEpoch;
        try {
            iatEpoch = Long.parseLong(iatObj.toString());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid JWT payload: iat must be a numeric epoch value", e);
        }

        Instant iat = Instant.ofEpochSecond(iatEpoch);
        Instant now = Instant.now();

        if (iat.isBefore(now.minusSeconds(300)) || iat.isAfter(now.plusSeconds(60))) {
            throw new IllegalArgumentException("Invalid JWT payload: iat outside acceptable time window");
        }

        if (payload.containsKey("exp")) {
            Object expObj = payload.get("exp");
            long expEpoch;
            try {
                expEpoch = Long.parseLong(expObj.toString());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid JWT payload: exp must be a numeric epoch value", e);
            }

            Instant exp = Instant.ofEpochSecond(expEpoch);
            if (now.isAfter(exp)) {
                throw new IllegalArgumentException("Invalid JWT payload: proof has expired");
            }
        }
    }


}
