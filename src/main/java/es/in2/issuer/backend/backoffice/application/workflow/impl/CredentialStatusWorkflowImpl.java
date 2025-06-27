package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.CredentialStatusWorkflow;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialStatusWorkflowImpl implements CredentialStatusWorkflow {

    private final CredentialStatusService credentialStatusService;

    @Override
    public Flux<String> getCredentialsStatusByListId(String processId, int listId) {
        return credentialStatusService.getCredentialsStatusByListId(listId)
                .doFirst(() -> log.debug("Process ID: {} - Getting Credentials Status...", processId))
                .doOnComplete(() -> log.debug(
                        "Process ID: {} - All Credential Status retrieved successfully.",
                        processId));
    }

    @Override
    public Mono<Void> revokeCredential(String processId, String credentialId, int listId) {
        return credentialStatusService.revokeCredential(credentialId, listId)
                .doFirst(() -> log.debug("Process ID: {} - Revoking Credential with ID: {}", processId, credentialId))
                .doOnSuccess(aVoid -> log.debug(
                        "Process ID: {} - Credential with ID: {} revoked successfully.",
                        processId,
                        credentialId));
    }
}