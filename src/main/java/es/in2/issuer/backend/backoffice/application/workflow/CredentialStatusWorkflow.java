package es.in2.issuer.backend.backoffice.application.workflow;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface CredentialStatusWorkflow {
    Mono<Void> revokeCredential(String processId, String bearerToken, String procedureId, int listId);
}