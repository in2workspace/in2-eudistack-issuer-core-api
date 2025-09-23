package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface PreAuthorizedCodeService {
    Mono<PreAuthorizedCodeResponse> generatePreAuthorizedCode(String processId, Mono<String> credentialProcedureIdMono);
}
