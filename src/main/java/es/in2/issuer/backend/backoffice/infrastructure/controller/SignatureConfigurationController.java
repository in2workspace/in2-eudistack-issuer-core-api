package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.exception.MissingRequiredDataException;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CompleteSignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigWithProviderName;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigurationResponse;
import es.in2.issuer.backend.backoffice.domain.model.dtos.UpdateSignatureConfigurationRequest;
import es.in2.issuer.backend.backoffice.domain.model.entities.SignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;
import es.in2.issuer.backend.backoffice.domain.service.SignatureConfigurationService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/backoffice/v1/signatures/configs")
@RequiredArgsConstructor
public class SignatureConfigurationController {

    private final SignatureConfigurationService signatureConfigurationService;
    private final AccessTokenService accessTokenService;

    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<SignatureConfiguration> createSignatureConfiguration(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestBody CompleteSignatureConfiguration config
    ) {

        log.debug("Creating signature configuration for organization: {}", config.organizationIdentifier());
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(orgId ->signatureConfigurationService.saveSignatureConfig( config, orgId));

    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public Flux<SignatureConfigWithProviderName> getAllSignatureConfigurations(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestParam(name = "signatureMode", required = false) SignatureMode signatureMode) {
        return accessTokenService.getOrganizationId(authorizationHeader)
                .doOnNext(orgId -> log.debug("Fetching signature configurations for org: {}", orgId))
                .flatMapMany(orgId ->signatureConfigurationService.findAllByOrganizationIdentifierAndMode(orgId, signatureMode));
    }

    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<SignatureConfigurationResponse>> getCompleteConfigurationById(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable String id) {

        log.debug("Fetching complete signature configuration for ID: {}", id);
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(organizationId -> signatureConfigurationService.getCompleteConfigurationById(id, organizationId)
                        .map(ResponseEntity::ok)
                        .switchIfEmpty(Mono.just(ResponseEntity.notFound().build())));
    }

    @PatchMapping(value = "/{id}", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> updateSignatureConfiguration(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable String id,
            @RequestBody UpdateSignatureConfigurationRequest updateRequest

    ) {
        if (updateRequest.rationale() == null || updateRequest.rationale().isBlank()) {
            return Mono.error(new MissingRequiredDataException("'rationale' must be provided"));
        }
        return
                accessTokenService.getOrganizationId(authorizationHeader)
                        .flatMap(organizationId -> accessTokenService.getMandateeEmail(authorizationHeader)
                                .flatMap(userEmail -> signatureConfigurationService.updateSignatureConfiguration(id, organizationId, updateRequest.toCompleteSignatureConfiguration(),updateRequest.rationale(), userEmail)));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> deleteSignatureConfiguration(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable String id,
            @RequestParam() String rationale
    ) {
        log.debug("Deleting signature configuration with ID: {} and rationale: {}", id, rationale);
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(organizationId -> accessTokenService.getMandateeEmail(authorizationHeader)
                        .flatMap(userEmail ->signatureConfigurationService.deleteSignatureConfiguration( id, organizationId, rationale, userEmail)));

    }

}