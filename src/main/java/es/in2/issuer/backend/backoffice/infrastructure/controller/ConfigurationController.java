package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.service.ConfigurationService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/backoffice/v1/configuration")
@RequiredArgsConstructor
@Slf4j
public class ConfigurationController {
    private final AccessTokenService accessTokenService;
    private final ConfigurationService configurationService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> saveConfiguration(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
                                                        @RequestBody Map<String, String> settings) {
        return accessTokenService.getOrganizationId(authorizationHeader)
                .doOnNext(orgId -> log.debug("Saving config for organization : {}", orgId))
                .flatMap(orgId -> configurationService.saveConfiguration(orgId, settings));

    }

    @GetMapping
    public Mono<Map<String, String>> getConfigurationsByOrganization(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader
    ) {
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(configurationService::getConfigurationMapByOrganization);
    }

    @PatchMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> patchConfigurations(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestBody Map<String, String> updates
    ) {
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(orgId -> configurationService.updateOrInsertKeys(orgId, updates));
    }

}
