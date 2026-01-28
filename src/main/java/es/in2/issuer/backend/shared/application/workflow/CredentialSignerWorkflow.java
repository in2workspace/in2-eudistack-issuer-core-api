package es.in2.issuer.backend.shared.application.workflow;

import reactor.core.publisher.Mono;

public interface CredentialSignerWorkflow {
    Mono<String> signAndUpdateCredentialByProcedureId(String processId, String authorizationHeader, String procedureId, String format, String email);

    Mono<Void> retrySignUnsignedCredential(String processId, String authorizationHeader, String procedureId);
}
