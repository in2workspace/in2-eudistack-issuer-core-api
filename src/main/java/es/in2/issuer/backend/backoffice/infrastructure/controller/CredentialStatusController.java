package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.application.workflow.CredentialStatusWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialStatusResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/backoffice/v1/credentials/status")
@RequiredArgsConstructor
public class CredentialStatusController {

    private final CredentialStatusWorkflow credentialStatusWorkflow;

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public Flux<CredentialStatusResponse> getCredentialsStatus() {
        String processId = UUID.randomUUID().toString();

        return credentialStatusWorkflow.getCredentialsStatus(processId)
                .doFirst(() -> log.info("Process ID: {} - Getting Credentials Status...", processId))
                .map(CredentialStatusResponse::new)
                .doOnComplete(() -> log.info("Process ID: {} - All Credential Status retrieved successfully.", processId));
    }
}
