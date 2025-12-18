package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.shared.application.workflow.NonceValidationWorkflow;
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
    private final NonceValidationWorkflow nonceValidationWorkflow;


    @Override
    public Mono<Boolean> isProofValid(String jwtProof, String token, Set<String> allowedAlgs) {
        return Mono.just(jwtProof)
                .doOnNext(jwt -> log.debug("Starting validation for JWT: {}", jwt))
                .flatMap(jwt -> parseAndValidateJwt(jwt, allowedAlgs))
                .doOnNext(jws -> log.debug("JWT parsed successfully"))
                .flatMap(jwsObject ->
                        jwtService.validateJwtSignatureReactive(jwsObject)
                                .doOnSuccess(isSignatureValid -> log.debug("Signature validation result: {}", isSignatureValid))
                                .map(isSignatureValid -> Boolean.TRUE.equals(isSignatureValid) ? jwsObject : null)
                )
                .doOnNext(jwsObject -> {
                    if (jwsObject == null) log.debug("JWT signature validation failed");
                    else log.debug("JWT signature validated, checking nonce...");
                })
                .map(Objects::nonNull)
                // TODO: Check nonce when implemented
                .doOnSuccess(result -> log.debug("Final validation result: {}", result))
                .onErrorMap(e -> new ProofValidationException("Error during JWT validation"));
    }

    private Mono<JWSObject> parseAndValidateJwt(String jwtProof, Set<String> allowedAlgs) {
        return Mono.fromCallable(() -> {
            JWSObject jwsObject = JWSObject.parse(jwtProof);
            validateHeader(jwsObject, allowedAlgs);
            validatePayload(jwsObject);
            return jwsObject;
        });
    }

    private void validateHeader(JWSObject jwsObject, Set<String> allowedAlgs) {
        Map<String, Object> headerParams = jwsObject.getHeader().toJSONObject();


        Object algObj = headerParams.get("alg");
        Object typObj = headerParams.get("typ");

        if (algObj == null || typObj == null) {
            throw new IllegalArgumentException("Invalid JWT header: alg or typ missing");
        }

        String alg = algObj.toString();
        String typ = typObj.toString();

        if (!SUPPORTED_PROOF_TYP.equals(typ)) {
            throw new IllegalArgumentException("Invalid JWT header: unsupported typ");
        }

        if ("none".equalsIgnoreCase(alg) || alg.toUpperCase().startsWith("HS")) {
            throw new IllegalArgumentException("Invalid JWT header: alg must be asymmetric and not 'none'");
        }

        if (allowedAlgs != null && !allowedAlgs.isEmpty()) {
            if (!allowedAlgs.contains(alg)) {
                throw new IllegalArgumentException(
                        "Invalid JWT header: alg '" + alg + "' not allowed by issuer configuration " + allowedAlgs);
            }
        } else {
            if (!SUPPORTED_PROOF_ALG.equals(alg)) {
                throw new IllegalArgumentException("Invalid JWT header: alg not supported");
            }
        }

        boolean hasKid = headerParams.containsKey("kid");
        boolean hasJwk = headerParams.containsKey("jwk");
        boolean hasX5c = headerParams.containsKey("x5c");
        int keyRefCount = (hasKid ? 1 : 0) + (hasJwk ? 1 : 0) + (hasX5c ? 1 : 0);

        if (keyRefCount != 1) {
            throw new IllegalArgumentException(
                    "Invalid JWT header: exactly one of kid, jwk or x5c must be present");
        }

        if (hasJwk) {
            Object jwkObj = headerParams.get("jwk");
            if (jwkObj instanceof Map<?, ?> jwkMap) {
                if (jwkMap.containsKey("d")
                        || jwkMap.containsKey("p")
                        || jwkMap.containsKey("q")
                        || jwkMap.containsKey("dp")
                        || jwkMap.containsKey("dq")
                        || jwkMap.containsKey("qi")) {
                    throw new IllegalArgumentException("Invalid JWT header: JWK must not contain private key material");
                }
            }
        }
    }



    private void validatePayload(JWSObject jwsObject) {
        var payload = jwsObject.getPayload().toJSONObject();

        Object audObj = payload.get("aud");
        if (audObj == null || audObj.toString().isBlank()) {
            throw new IllegalArgumentException("Invalid JWT payload: aud is missing");
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
