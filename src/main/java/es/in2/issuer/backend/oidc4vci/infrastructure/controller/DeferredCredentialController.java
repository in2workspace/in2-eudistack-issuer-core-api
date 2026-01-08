package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/deferred-credential")
@RequiredArgsConstructor
public class DeferredCredentialController {

    private final CredentialIssuanceWorkflow credentialIssuanceWorkflow;

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<DeferredCredentialResponse> getCredential(
            @RequestBody DeferredCredentialRequest deferredCredentialRequest) {
        String processId = UUID.randomUUID().toString();
        return credentialIssuanceWorkflow.generateVerifiableCredentialDeferredResponse(
                        processId,
                        deferredCredentialRequest)
                .doFirst(() ->
                        log.info("Process ID: {} - Creating Deferred Verifiable Credential...", processId))
                .doOnSuccess(credentialOffer ->
                        log.info("Process ID: {} - Deferred Verifiable Credential created successfully.", processId));
    }
}
