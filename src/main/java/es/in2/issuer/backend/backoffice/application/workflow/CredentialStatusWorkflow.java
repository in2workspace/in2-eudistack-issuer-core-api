package es.in2.issuer.backend.backoffice.application.workflow;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface CredentialStatusWorkflow {
    Flux<String> getCredentialsStatusByListId(String processId, int listId);

    Mono<Void> revokeCredential(String processId, String credentialId, int listId);
}
