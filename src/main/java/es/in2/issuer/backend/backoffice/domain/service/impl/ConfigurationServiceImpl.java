package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.model.entities.Configuration;
import es.in2.issuer.backend.backoffice.domain.repository.ConfigurationRepository;
import es.in2.issuer.backend.backoffice.domain.service.ConfigurationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class ConfigurationServiceImpl implements ConfigurationService {

    private final ConfigurationRepository configurationRepository;

    @Override
    public Mono<Void> saveConfiguration(String orgId, Map<String,String> settings){
        return Flux.fromIterable(settings.entrySet())
                .map(entry -> Configuration.builder()
                        .organizationIdentifier(orgId)
                        .configKey(entry.getKey())
                        .configvalue(entry.getValue())
                        .build())
                .collectList()
                .flatMapMany(configurationRepository::saveAll)
                .then(Mono.empty());
    }

    @Override
    public Mono<Map<String, String>> getConfigurationMapByOrganization(String orgId) {
        return configurationRepository.findAllByOrganizationIdentifier(orgId)
                .collectMap(Configuration::getConfigKey, Configuration::getConfigvalue);
    }

    @Override
    public Mono<Void> updateOrInsertKeys(String orgId, Map<String, String> updates) {
        return configurationRepository.findAllByOrganizationIdentifier(orgId)
                .collectMap(Configuration::getConfigKey)
                .flatMapMany(existingConfigs -> Flux.fromIterable(updates.entrySet())
                        .map(entry -> {
                            Configuration existing = existingConfigs.get(entry.getKey());
                            if (existing != null) {
                                existing.setConfigvalue(entry.getValue());
                                return existing;
                            } else { //  check Uri
                                return Configuration.builder()
                                        .organizationIdentifier(orgId)
                                        .configKey(entry.getKey())
                                        .configvalue(entry.getValue())
                                        .build();
                            }
                        })
                )
                .collectList()
                .flatMapMany(configurationRepository::saveAll)
                .then();
    }

}
