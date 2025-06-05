package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import reactor.core.publisher.Mono;

public interface TokenWorkflow {
    Mono<TokenResponse> generateTokenResponse(String grantType, String preAuthorizedCode, String txCode);
}
