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

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SUPPORTED_PROOF_ALG;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SUPPORTED_PROOF_TYP;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProofValidationServiceImpl implements ProofValidationService {

    private final JWTService jwtService;
    private final NonceValidationWorkflow nonceValidationWorkflow;


    @Override
    public Mono<Boolean> isProofValid(String jwtProof, String token) {
        return Mono.just(jwtProof)
                .doOnNext(jwt -> log.debug("Starting validation for JWT: {}", jwt))
                .flatMap(this::parseAndValidateJwt)
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

    private Mono<JWSObject> parseAndValidateJwt(String jwtProof) {
        return Mono.fromCallable(() -> {
            JWSObject jwsObject = JWSObject.parse(jwtProof);
            validateHeader(jwsObject);
            validatePayload(jwsObject);
            return jwsObject;
        });
    }

    private void validateHeader(JWSObject jwsObject) {
        Map<String, Object> headerParams = jwsObject.getHeader().toJSONObject();
        if (headerParams.get("alg") == null || headerParams.get("typ") == null ||
                !SUPPORTED_PROOF_ALG.equals(headerParams.get("alg")) ||
                !SUPPORTED_PROOF_TYP.equals(headerParams.get("typ"))) {
            throw new IllegalArgumentException("Invalid JWT header");
        }
    }

    private void validatePayload(JWSObject jwsObject) {
        var payload = jwsObject.getPayload().toJSONObject();
        if (!payload.containsKey("aud") || !payload.containsKey("iat") ||
                (payload.containsKey("exp") && Instant.now().isAfter(Instant.ofEpochSecond(Long.parseLong(payload.get("exp").toString()))))) {
            throw new IllegalArgumentException("Invalid JWT payload");
        }
    }
}
