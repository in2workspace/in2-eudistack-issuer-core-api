package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CloudProviderRequest;
import es.in2.issuer.backend.backoffice.domain.model.entities.CloudProvider;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface CloudProviderService {
    Mono<CloudProvider> save(CloudProviderRequest provider);
    Flux<CloudProvider> findAll();
    Mono<Boolean> requiresTOTP(UUID cloudProviderId);
    Mono<CloudProvider> findById(UUID id);
}
