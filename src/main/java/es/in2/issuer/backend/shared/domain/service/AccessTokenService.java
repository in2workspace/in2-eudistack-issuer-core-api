package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import reactor.core.publisher.Mono;

public interface AccessTokenService {
    Mono<String> getCleanBearerToken(String authorizationHeader);
    Mono<String> getUserId(String authorizationHeader);
    Mono<String> getOrganizationId(String authorizationHeader);
    Mono<String> getOrganizationIdFromCurrentSession();
    Mono<String> getMandateeEmail(String authorizationHeader);
    Mono<AccessTokenContext> validateAndResolveProcedure(String authorizationHeader);

}
