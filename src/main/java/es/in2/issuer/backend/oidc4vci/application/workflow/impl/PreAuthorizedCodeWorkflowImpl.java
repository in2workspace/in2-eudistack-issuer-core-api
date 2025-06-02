package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.PreAuthorizedCodeWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PreAuthorizedCodeWorkflowImpl implements PreAuthorizedCodeWorkflow {
    private final PreAuthorizedCodeService preAuthorizedCodeService;

    @Override
    public Mono<PreAuthorizedCodeResponse> generatePreAuthorizedCode() {
        String processId = UUID.randomUUID().toString();
        return preAuthorizedCodeService.generatePreAuthorizedCode(processId)
                .doFirst(() -> log.info("ProcessId: {} AuthServer: Starting PreAuthorizedCode generation", processId))
                .doOnSuccess(preAuthorizedCodeResponse ->
                        log.info(
                                "ProcessId: {} AuthServer: PreAuthorizedCode generation completed successfully",
                                processId));
    }

}
