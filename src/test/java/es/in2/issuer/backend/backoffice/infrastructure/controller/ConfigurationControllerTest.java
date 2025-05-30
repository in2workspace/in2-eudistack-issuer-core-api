package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.service.ConfigurationService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ConfigurationControllerTest {

    @Mock AccessTokenService accessTokenService;
    @Mock ConfigurationService configurationService;
    @InjectMocks ConfigurationController controller;

    private static final String AUTH = "Bearer token";
    private static final String ORG = "org-123";
    private Map<String, String> settings;

    @BeforeEach
    void setUp() {
        settings = Map.of("k1", "v1", "k2", "v2");
    }

    @Test
    void saveConfiguration_success() {
        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG));
        when(configurationService.saveConfiguration(ORG, settings)).thenReturn(Mono.empty());

        Mono<Void> result = controller.saveConfiguration(AUTH, settings);

        StepVerifier.create(result)
                .verifyComplete();

        verify(accessTokenService).getOrganizationId(AUTH);
        verify(configurationService).saveConfiguration(ORG, settings);
    }

    @Test
    void saveConfiguration_orgError() {
        when(accessTokenService.getOrganizationId(AUTH))
                .thenReturn(Mono.error(new RuntimeException("no auth")));

        StepVerifier.create(controller.saveConfiguration(AUTH, settings))
                .expectErrorMatches(e ->
                        e instanceof RuntimeException &&
                                e.getMessage().equals("no auth")
                )
                .verify();

        verify(configurationService, never()).saveConfiguration(anyString(), anyMap());
    }

    @Test
    void getConfigurationsByOrganization_success() {
        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG));
        when(configurationService.getConfigurationMapByOrganization(ORG))
                .thenReturn(Mono.just(settings));

        Mono<Map<String, String>> result =
                controller.getConfigurationsByOrganization(AUTH);

        StepVerifier.create(result)
                .assertNext(resp -> {
                    assertThat(resp).isEqualTo(settings);
                })
                .verifyComplete();

        verify(accessTokenService).getOrganizationId(AUTH);
        verify(configurationService).getConfigurationMapByOrganization(ORG);
    }

    @Test
    void getConfigurationsByOrganization_error() {
        when(accessTokenService.getOrganizationId(AUTH))
                .thenReturn(Mono.error(new RuntimeException("fail")));

        StepVerifier.create(controller.getConfigurationsByOrganization(AUTH))
                .expectErrorMessage("fail")
                .verify();

        verify(configurationService, never()).getConfigurationMapByOrganization(anyString());
    }

    @Test
    void patchConfigurations_success() {
        when(accessTokenService.getOrganizationId(AUTH)).thenReturn(Mono.just(ORG));
        when(configurationService.updateOrInsertKeys(ORG, settings)).thenReturn(Mono.empty());

        Mono<Void> result = controller.patchConfigurations(AUTH, settings);

        StepVerifier.create(result)
                .verifyComplete();

        verify(accessTokenService).getOrganizationId(AUTH);
        verify(configurationService).updateOrInsertKeys(ORG, settings);
    }

    @Test
    void patchConfigurations_error() {
        when(accessTokenService.getOrganizationId(AUTH))
                .thenReturn(Mono.just(ORG));
        when(configurationService.updateOrInsertKeys(ORG, settings))
                .thenReturn(Mono.error(new IllegalStateException("oops")));

        StepVerifier.create(controller.patchConfigurations(AUTH, settings))
                .expectErrorMatches(e ->
                        e instanceof IllegalStateException &&
                                e.getMessage().equals("oops")
                )
                .verify();
    }
}