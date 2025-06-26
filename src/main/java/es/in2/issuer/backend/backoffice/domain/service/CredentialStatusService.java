package es.in2.issuer.backend.backoffice.domain.service;

import reactor.core.publisher.Flux;

public interface CredentialStatusService {
    Flux<String> getCredentialsStatus();
}
