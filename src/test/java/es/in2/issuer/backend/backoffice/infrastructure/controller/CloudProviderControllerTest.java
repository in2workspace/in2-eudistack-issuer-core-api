package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CloudProviderRequest;
import es.in2.issuer.backend.backoffice.domain.model.entities.CloudProvider;
import es.in2.issuer.backend.backoffice.domain.service.CloudProviderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
class CloudProviderControllerTest {

    @Mock
    private CloudProviderService cloudProviderService;

    @InjectMocks
    private CloudProviderController controller;

    private static final String AUTH = "Bearer dummy-token";
    private CloudProviderRequest request;
    private CloudProvider savedEntity;

    @BeforeEach
    void setUp() {
        UUID id = UUID.randomUUID();
        request = CloudProviderRequest.builder()
                .provider("ProviderX")
                .url("https://provider.x")
                .authMethod("method")
                .authGrantType("grant")
                .requiresTOTP(true)
                .build();

        savedEntity = CloudProvider.builder()
                .id(id)
                .provider(request.provider())
                .url(request.url())
                .authMethod(request.authMethod())
                .authGrantType(request.authGrantType())
                .requiresTOTP(request.requiresTOTP())
                .build();
    }

    @Test
    void createCloudProvider_success() {
        when(cloudProviderService.save(request))
                .thenReturn(Mono.just(savedEntity));

        // ahora devuelve Mono<CloudProvider> directamente
        StepVerifier.create(controller.createCloudProvider(AUTH, request))
                .assertNext(cp -> {
                    assertThat(cp).isEqualTo(savedEntity);
                })
                .verifyComplete();

        verify(cloudProviderService).save(request);
    }

    @Test
    void createCloudProvider_errorPropagates() {
        when(cloudProviderService.save(request))
                .thenReturn(Mono.error(new IllegalStateException("fail")));

        StepVerifier.create(controller.createCloudProvider(AUTH, request))
                .expectErrorMatches(e ->
                        e instanceof IllegalStateException &&
                                e.getMessage().equals("fail")
                )
                .verify();

        verify(cloudProviderService).save(request);
    }

    @Test
    void getAllCloudProviders_success() {
        CloudProvider other = CloudProvider.builder()
                .id(UUID.randomUUID())
                .provider("Other")
                .url("u")
                .authMethod("m")
                .authGrantType("g")
                .requiresTOTP(false)
                .build();

        when(cloudProviderService.findAll())
                .thenReturn(Flux.just(savedEntity, other));

        StepVerifier.create(controller.getAllCloudProviders(AUTH))
                .assertNext(cp -> assertThat(cp).isEqualTo(savedEntity))
                .assertNext(cp -> assertThat(cp).isEqualTo(other))
                .verifyComplete();

        verify(cloudProviderService).findAll();
    }

    @Test
    void getAllCloudProviders_errorPropagates() {
        when(cloudProviderService.findAll())
                .thenReturn(Flux.error(new RuntimeException("oops")));

        StepVerifier.create(controller.getAllCloudProviders(AUTH))
                .expectErrorMessage("oops")
                .verify();

        verify(cloudProviderService).findAll();
    }
}