package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CloudProviderRequest;
import es.in2.issuer.backend.backoffice.domain.model.entities.CloudProvider;
import es.in2.issuer.backend.backoffice.domain.repository.CloudProviderRepository;
import es.in2.issuer.backend.backoffice.domain.service.CloudProviderService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CloudProviderServiceImpl implements CloudProviderService {
    private final CloudProviderRepository repository;

    @Override
    public Mono<CloudProvider> save(CloudProviderRequest provider){

        return buildCloudProvider(provider)
                .flatMap(repository::save);
    }

    @Override
    public Flux<CloudProvider> findAll(){
        return repository.findAll();
    }

    @Override
    public Mono<Boolean> requiresTOTP(UUID cloudProviderId) {
        return repository.findById(cloudProviderId)
                .map(CloudProvider::isRequiresTOTP)
                .defaultIfEmpty(false);
    }

    @Override
    public Mono<CloudProvider> findById(UUID id) {
        return repository.findById(id);
    }

    private Mono<CloudProvider> buildCloudProvider(CloudProviderRequest request) {
        return Mono.just(
                CloudProvider.builder()
                        .provider(request.provider())
                        .url(request.url())
                        .authMethod(request.authMethod())
                        .authGrantType(request.authGrantType())
                        .requiresTOTP(request.requiresTOTP())
                .build()
        );
    }
}
