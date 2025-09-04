package es.in2.issuer.backend.oidc4vci.infrastructure.controller;


import es.in2.issuer.backend.oidc4vci.application.workflow.CredentialOfferWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.ENGLISH;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/credential-offer")
@RequiredArgsConstructor
public class CredentialOfferController {

    private final CredentialOfferWorkflow credentialOfferWorkflow;

    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialOffer> getCredentialOfferByReference(@PathVariable("id") String id, ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().add(HttpHeaders.CONTENT_LANGUAGE, ENGLISH);
        log.info("CredentialOfferController");
        return credentialOfferWorkflow.getCredentialOfferById(processId, id)
                .doFirst(() ->
                        log.info("Process ID: {} - Getting Credential Offer by its reference...", processId))
                .doOnSuccess(credentialOffer ->
                        log.info("Process ID: {} - Credential Offer retrieved successfully.", processId));
    }

}
