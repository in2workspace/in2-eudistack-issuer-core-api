package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.ActivationCodeRequest;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/backoffice/v1/credentials/activate")
@RequiredArgsConstructor
public class ActivationCodeController {

    private final ActivationCodeWorkflow activationCodeWorkflow;

    @PostMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialOfferUriResponse> getCredentialOfferByActivationCode(
            @RequestBody ActivationCodeRequest activationCodeRequest) {
        log.info("Retrieving Credential Offer with Activation Code...");
        String processId = UUID.randomUUID().toString();

        if (hasActivationCode(activationCodeRequest)) {
            return activationCodeWorkflow.buildCredentialOfferUri(
                    processId,
                    activationCodeRequest.activationCode());
        } else if (hasCActivationCode(activationCodeRequest)) {
            return activationCodeWorkflow.buildNewCredentialOfferUri(
                    processId,
                    activationCodeRequest.c_activationCode());
        } else {
            log.error("Error getting activationCode or cActivationCode. Either 'activationCode' or 'cActivationCode' " +
                    "must be provided, but not both.");
            return Mono.error(new IllegalArgumentException("Either 'activationCode' or 'cActivationCode' must be " +
                    "provided, but not both."));
        }
    }

    private static boolean hasCActivationCode(ActivationCodeRequest activationCodeRequest) {
        return activationCodeRequest.c_activationCode() != null && !activationCodeRequest.c_activationCode().isEmpty()
                && (activationCodeRequest.activationCode() == null || activationCodeRequest.activationCode().isEmpty());
    }

    private static boolean hasActivationCode(ActivationCodeRequest activationCodeRequest) {
        return activationCodeRequest.activationCode() != null && !activationCodeRequest.activationCode().isEmpty()
                && (activationCodeRequest.c_activationCode() == null
                || activationCodeRequest.c_activationCode().isEmpty());
    }
}