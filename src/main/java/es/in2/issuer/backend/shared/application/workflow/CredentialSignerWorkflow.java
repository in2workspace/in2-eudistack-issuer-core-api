package es.in2.issuer.backend.shared.application.workflow;

import reactor.core.publisher.Mono;

public interface CredentialSignerWorkflow {
    Mono<String> signAndUpdateCredentialByProcedureId(String authorizationHeader, String procedureId, String format);

    Mono<String> signAndUpdateCredential(
            String credentialId,
            String credentialFormat,
            String credentialType,
            String credentialJson,
            String authorizationHeader);

    Mono<Void> retrySignUnsignedCredential(String authorizationHeader, String procedureId);
}
