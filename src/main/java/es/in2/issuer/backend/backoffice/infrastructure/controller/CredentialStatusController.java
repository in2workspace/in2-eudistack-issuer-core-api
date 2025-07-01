package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.application.workflow.CredentialStatusWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialStatusResponse;
import es.in2.issuer.backend.backoffice.domain.model.dtos.RevokeCredentialRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/backoffice/v1/credentials/status")
@RequiredArgsConstructor
public class CredentialStatusController {

    private final CredentialStatusWorkflow credentialStatusWorkflow;

    @GetMapping("/{listId}")
    @ResponseStatus(HttpStatus.OK)
    public Flux<CredentialStatusResponse> getCredentialsStatus(@PathVariable int listId) {
        String processId = UUID.randomUUID().toString();

        return credentialStatusWorkflow.getCredentialsStatusByListId(processId, listId)
                .doFirst(() -> log.info("Process ID: {} - Getting Credentials Status...", processId))
                .map(CredentialStatusResponse::new)
                .doOnComplete(() -> log.info(
                        "Process ID: {} - All Credential Status retrieved successfully.",
                        processId));
    }

    @PostMapping("/revoke")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> revokeCredential(@RequestBody RevokeCredentialRequest revokeCredentialRequest) {
        String processId = UUID.randomUUID().toString();

        return credentialStatusWorkflow.revokeCredential(
                        processId,
                        revokeCredentialRequest.credentialId(),
                        revokeCredentialRequest.listId())
                .doFirst(() -> log.info("Process ID: {} - Revoking Credential...", processId))
                .doOnSuccess(result -> log.info("Process ID: {} - Credential revoked successfully.", processId));
    }
}
