package es.in2.issuer.backend.shared.domain.service;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;

public interface JWTService {

    String generateJWT(String payload);

    Mono<Boolean> validateJwtSignatureReactive(JWSObject jwsObject);

    Mono<Boolean> validateJwtSignatureWithJwkReactive(String jwt, Map<String,Object> jwkMap);

    SignedJWT parseJWT(String jwt);

    Payload getPayloadFromSignedJWT(SignedJWT signedJWT);

    String getClaimFromPayload(Payload payload, String claimName);

    Long getExpirationFromToken(String token);

    String resolvePrincipal(Jwt jwt);

    Optional<String> extractMandateeEmail(Jwt jwt);
}
