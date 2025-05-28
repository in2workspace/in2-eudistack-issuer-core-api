package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.model.entities.Configuration;
import es.in2.issuer.backend.backoffice.domain.repository.ConfigurationRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ConfigurationServiceImplTest {

    @Mock
    private ConfigurationRepository configurationRepository;

    @InjectMocks
    private ConfigurationServiceImpl configurationServiceImpl;

    private static final String ORG_ID = "org-1";

    @Test
    void testSaveConfiguration() {
        Map<String, String> settings = Map.of(
                "key1", "value1",
                "key2", "value2"
        );

        when(configurationRepository.saveAll(anyList()))
                .thenAnswer(invocation -> {
                    List<Configuration> toSave = invocation.getArgument(0);
                    return Flux.fromIterable(toSave);
                });

        Mono<Void> result = configurationServiceImpl.saveConfiguration(ORG_ID, settings);

        StepVerifier.create(result)
                .verifyComplete();

        ArgumentCaptor<List<Configuration>> captor = ArgumentCaptor.forClass(List.class);
        verify(configurationRepository, times(1)).saveAll(captor.capture());

        List<Configuration> saved = captor.getValue();
        assertThat(saved).hasSize(2);
        // Verify that the configurations have the correct organization identifier
        Map<String, String> asMap = new HashMap<>();
        for (Configuration c : saved) {
            asMap.put(c.getConfigKey(), c.getConfigvalue());
            assertThat(c.getOrganizationIdentifier()).isEqualTo(ORG_ID);
        }
        assertThat(asMap).containsExactlyInAnyOrderEntriesOf(settings);
    }

    @Test
    void testGetConfigurationMapByOrganization() {
        List<Configuration> existing = List.of(
                Configuration.builder()
                        .organizationIdentifier(ORG_ID)
                        .configKey("a")
                        .configvalue("1")
                        .build(),
                Configuration.builder()
                        .organizationIdentifier(ORG_ID)
                        .configKey("b")
                        .configvalue("2")
                        .build()
        );

        when(configurationRepository.findAllByOrganizationIdentifier(ORG_ID))
                .thenReturn(Flux.fromIterable(existing));

        Mono<Map<String, String>> result = configurationServiceImpl.getConfigurationMapByOrganization(ORG_ID);

        StepVerifier.create(result)
                .assertNext(map -> assertThat(map)
                        .hasSize(2)
                        .containsEntry("a", "1")
                        .containsEntry("b", "2"))
                .verifyComplete();
    }

    @Test
    void testUpdateOrInsertKeys_ExistingAndNew() {
        // Verify that the repository returns an existing configuration
        Configuration existing = Configuration.builder()
                .organizationIdentifier(ORG_ID)
                .configKey("k1")
                .configvalue("old")
                .build();

        when(configurationRepository.findAllByOrganizationIdentifier(ORG_ID))
                .thenReturn(Flux.just(existing));

        Map<String, String> updates = Map.of(
                "k1", "new1",
                "k2", "new2"
        );

        when(configurationRepository.saveAll(anyList()))
                .thenAnswer(invocation -> {
                    List<Configuration> list = invocation.getArgument(0);
                    return Flux.fromIterable(list);
                });

        Mono<Void> result = configurationServiceImpl.updateOrInsertKeys(ORG_ID, updates);

        StepVerifier.create(result)
                .verifyComplete();

        ArgumentCaptor<List<Configuration>> captor = ArgumentCaptor.forClass(List.class);
        verify(configurationRepository, times(1)).saveAll(captor.capture());
        List<Configuration> saved = captor.getValue();

        assertThat(saved).hasSize(2);
        Map<String, String> map = new HashMap<>();
        for (Configuration c : saved) {
            map.put(c.getConfigKey(), c.getConfigvalue());
            assertThat(c.getOrganizationIdentifier()).isEqualTo(ORG_ID);
        }
        assertThat(map)
                .containsEntry("k1", "new1")
                .containsEntry("k2", "new2");
    }

    @Test
    void testUpdateOrInsertKeys_NoExisting() {
        when(configurationRepository.findAllByOrganizationIdentifier(ORG_ID))
                .thenReturn(Flux.empty());

        Map<String, String> updates = Map.of(
                "x", "X",
                "y", "Y"
        );

        when(configurationRepository.saveAll(anyList()))
                .thenAnswer(invocation -> {
                    List<Configuration> list = invocation.getArgument(0);
                    return Flux.fromIterable(list);
                });

        Mono<Void> result = configurationServiceImpl.updateOrInsertKeys(ORG_ID, updates);

        StepVerifier.create(result)
                .verifyComplete();

        ArgumentCaptor<List<Configuration>> captor = ArgumentCaptor.forClass(List.class);
        verify(configurationRepository, times(1)).saveAll(captor.capture());
        List<Configuration> saved = captor.getValue();

        assertThat(saved).hasSize(2);
        Map<String, String> map = new HashMap<>();
        for (Configuration c : saved) {
            map.put(c.getConfigKey(), c.getConfigvalue());
            assertThat(c.getOrganizationIdentifier()).isEqualTo(ORG_ID);
        }
        assertThat(map)
                .containsEntry("x", "X")
                .containsEntry("y", "Y");
    }
}
