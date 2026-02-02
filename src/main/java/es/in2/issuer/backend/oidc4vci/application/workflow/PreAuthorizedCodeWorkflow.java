package es.in2.issuer.backend.oidc4vci.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import reactor.core.publisher.Mono;

public interface PreAuthorizedCodeWorkflow {
    Mono<PreAuthorizedCodeResponse> generatePreAuthorizedCode(Mono<String> credentialProcedureIdMono);
}
