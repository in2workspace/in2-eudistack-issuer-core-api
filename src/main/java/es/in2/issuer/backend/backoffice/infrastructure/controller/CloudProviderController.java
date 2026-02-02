package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CloudProviderRequest;
import es.in2.issuer.backend.backoffice.domain.model.entities.CloudProvider;
import es.in2.issuer.backend.backoffice.domain.service.CloudProviderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping
public class CloudProviderController {
    private final CloudProviderService cloudProviderService;

    @PostMapping(path = "/ops/v1/signatures/cloud-providers", //TODO: debería ser backoffice? obsoleta?
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<CloudProvider> createCloudProvider(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestBody CloudProviderRequest request) {
        log.debug("Creating new cloud provider: {}", request.provider());
        return cloudProviderService.save(request);
    }

    @GetMapping(path = "/backoffice/v1/signatures/cloud-providers",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Flux<CloudProvider> getAllCloudProviders(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        log.debug("Fetching all cloud providers");
        return cloudProviderService.findAll();
    }

}
