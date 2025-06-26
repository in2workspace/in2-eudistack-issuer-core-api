package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.CredentialStatusWorkflow;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialStatusWorkflowImpl implements CredentialStatusWorkflow {

    private final CredentialStatusService credentialStatusService;

    @Override
    public Flux<String> getCredentialsStatus(String processId) {
        return credentialStatusService.getCredentialsStatus()
                .doFirst(() -> log.debug("Process ID: {} - Getting Credentials Status...", processId))
                .doOnComplete(() -> log.debug("Process ID: {} - All Credential Status retrieved successfully.", processId));
    }
}
