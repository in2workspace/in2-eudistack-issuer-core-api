package es.in2.issuer.backend.shared.infrastructure.config.security.service;

import com.fasterxml.jackson.databind.JsonNode;
import reactor.core.publisher.Mono;

public interface VerifiableCredentialPolicyAuthorizationService {
    Mono<Void> authorize(String authorizationHeader, String schema, JsonNode payload, String idToken);
}
