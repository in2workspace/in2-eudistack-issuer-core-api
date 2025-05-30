package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/credential-offer")
@RequiredArgsConstructor
public class ActivationCodeController {

    private final ActivationCodeWorkflow activationCodeWorkflow;

    @GetMapping("/transaction-code/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialOfferUriResponse> getCredentialOfferByTransactionCode(@PathVariable("id") String transactionCode) {
        log.info("Retrieving Credential Offer with Transaction Code...");
        String processId = UUID.randomUUID().toString();
        return activationCodeWorkflow.buildCredentialOfferUri(processId, transactionCode)
                .doOnSuccess(credentialOfferUri -> {
                            log.debug("Credential Offer URI created successfully: {}", credentialOfferUri);
                            log.info("Credential Offer created successfully.");
                        }
                );
    }

    @GetMapping("/c-transaction-code/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialOfferUriResponse> getCredentialOfferByCTransactionCode(@PathVariable("id") String cTransactionCode) {
        log.info("Retrieving Credential Offer with C Transaction Code...");
        String processId = UUID.randomUUID().toString();
        return activationCodeWorkflow.buildNewCredentialOfferUri(processId, cTransactionCode);
    }

}
