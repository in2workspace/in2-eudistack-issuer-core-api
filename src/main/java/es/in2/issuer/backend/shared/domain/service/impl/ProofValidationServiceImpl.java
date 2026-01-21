package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.ProofValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SUPPORTED_PROOF_TYP;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProofValidationServiceImpl implements ProofValidationService {

    private final JWTService jwtService;


    @Override
    public Mono<Boolean> isProofValid(String jwtProof, Set<String> allowedAlgs, String expectedAudience) {
        return Mono.just(jwtProof)
                .flatMap(jwt -> parseAndValidateJwt(jwt, expectedAudience, allowedAlgs))
                .doOnNext(jws -> log.debug("JWT parsed successfully"))
                .flatMap(signedJWT -> {
                    JWSHeader header = signedJWT.getHeader();

                    // 1) Si viene jwk
                    if (header.getJWK() != null) {
                        Map<String, Object> jwkMap = header.getJWK().toJSONObject();
                        return jwtService.validateJwtSignatureWithJwkReactive(signedJWT.serialize(), jwkMap);
                    }

                    // 2) Si NO viene jwk
                    return jwtService.validateJwtSignatureReactive(signedJWT);
                })
                .defaultIfEmpty(false)
                // TODO: Check nonce when implemented
                .doOnSuccess(result -> log.debug("Final validation result: {}", result))
                .onErrorMap(e -> (e instanceof ProofValidationException) ? e
                        : new ProofValidationException("Error during JWT validation"));
    }


    private Mono<SignedJWT> parseAndValidateJwt(String jwtProof, String expectedAudience, Set<String> allowedAlgs) {
        return Mono.fromCallable(() -> SignedJWT.parse(jwtProof))
                .flatMap(jwt -> {
                    try {
                        validateJwtHeader(jwt, allowedAlgs);
                    } catch (ProofValidationException e) {
                        return Mono.error(e);
                    }
                    validatePayload(jwt, expectedAudience);
                    return Mono.just(jwt);
                });
    }

    private void validateJwtHeader(SignedJWT signedJWT, Set<String> allowedAlgs) throws ProofValidationException {
        var header = signedJWT.getHeader();

        String alg = getAlg(header);
        validateAlgAllowed(alg, allowedAlgs);

        Map<String, Object> headerParams = header.toJSONObject();
        HeaderKeyMaterial km = resolveKeyMaterial(header, headerParams);

        // Not implemented: x5c
        if (km.type() == KeyMaterialType.X5C) {
            throw new ProofValidationException("invalid_proof: x5c not supported");
        }

        if (km.type() == KeyMaterialType.JWK) {
            validateJwkIsPublicOnly(km.value());
        }
    }

    private void validateAlgAllowed(String alg, Set<String> allowedAlgs) throws ProofValidationException {
        if (allowedAlgs == null || allowedAlgs.isEmpty() || !allowedAlgs.contains(alg)) {
            throw new ProofValidationException("invalid_proof: alg not allowed by configuration");
        }
    }

    private HeaderKeyMaterial resolveKeyMaterial(
            JWSHeader header,
            Map<String, Object> headerParams
    ) throws ProofValidationException {

        boolean hasKid = header.getKeyID() != null;
        Object jwkObj = headerParams.get("jwk");
        boolean hasJwk = jwkObj != null;

        Object x5cObj = headerParams.get("x5c");
        boolean hasX5c = (x5cObj instanceof java.util.List<?> list && !list.isEmpty());

        int present = (hasKid ? 1 : 0) + (hasJwk ? 1 : 0) + (hasX5c ? 1 : 0);
        if (present != 1) {
            throw new ProofValidationException("invalid_proof: exactly one of kid, jwk or x5c must be present");
        }

        if (hasKid) return new HeaderKeyMaterial(KeyMaterialType.KID, header.getKeyID());
        if (hasX5c) return new HeaderKeyMaterial(KeyMaterialType.X5C, x5cObj);
        return new HeaderKeyMaterial(KeyMaterialType.JWK, jwkObj);
    }

    private void validateJwkIsPublicOnly(Object jwkObj) throws ProofValidationException {
        if (!(jwkObj instanceof Map<?, ?> jwkMap)) {
            throw new ProofValidationException("invalid_proof: jwk must be a JSON object");
        }

        boolean hasPrivate =
                jwkMap.containsKey("d")  ||
                        jwkMap.containsKey("p")  ||
                        jwkMap.containsKey("q")  ||
                        jwkMap.containsKey("dp") ||
                        jwkMap.containsKey("dq") ||
                        jwkMap.containsKey("qi");

        if (hasPrivate) {
            throw new ProofValidationException("invalid_proof: JWK must not contain private key material");
        }
    }

    private enum KeyMaterialType { KID, JWK, X5C }

    private record HeaderKeyMaterial(KeyMaterialType type, Object value) {}


    private @NotNull String getAlg(JWSHeader header) throws ProofValidationException {
        String typ = header.getType() != null ? header.getType().toString() : null;
        String alg = header.getAlgorithm() != null ? header.getAlgorithm().getName() : null;

        if (!SUPPORTED_PROOF_TYP.equals(typ)) {
            throw new ProofValidationException("invalid_proof: typ must be openid4vci-proof+jwt");
        }
        if (alg == null || "none".equalsIgnoreCase(alg) || alg.startsWith("HS")) {
            throw new ProofValidationException("invalid_proof: alg not allowed");
        }
        return alg;
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
