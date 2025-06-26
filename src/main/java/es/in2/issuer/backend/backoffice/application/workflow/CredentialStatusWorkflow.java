package es.in2.issuer.backend.backoffice.application.workflow;

import reactor.core.publisher.Flux;

public interface CredentialStatusWorkflow {
    Flux<String> getCredentialsStatus(String processId);
}
