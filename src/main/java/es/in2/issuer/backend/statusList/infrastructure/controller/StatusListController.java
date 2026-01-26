package es.in2.issuer.backend.statusList.infrastructure.controller;

import es.in2.issuer.backend.statusList.application.RevocationWorkflow;
import es.in2.issuer.backend.statusList.application.StatusListWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.RevokeCredentialRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static java.util.Objects.requireNonNull;

//todo fix path, probably with "/status-list/v1/status"
@Slf4j
@RestController
@RequestMapping("/api/v1/status-list")
public class StatusListController {

    private static final MediaType VC_JWT = MediaType.parseMediaType("application/vc+jwt");
    private static final String VC_JWT_VALUE = "application/vc+jwt";

    private final StatusListWorkflow statusListWorkflow;
    private final RevocationWorkflow revocationService;

    public StatusListController(
            StatusListWorkflow statusListWorkflow,
            RevocationWorkflow revocationService
    ) {
        this.statusListWorkflow = requireNonNull(statusListWorkflow, "statusListService cannot be null");
        this.revocationService = requireNonNull(revocationService, "revocationService cannot be null");
    }

    /**
     * GET /api/v1/status-list/{listId}
     *
     * Non-legacy endpoint: always returns a signed Status List Credential as vc+jwt.
     */
    @GetMapping(value = "/{listId}", produces = VC_JWT_VALUE)
    public Mono<ResponseEntity<String>> getStatusList(@PathVariable Long listId) {
        String processId = UUID.randomUUID().toString();

        return statusListWorkflow.getSignedStatusListCredential(listId)
                .doFirst(() -> log.info("Process ID: {} - Getting Status List Credential (vc+jwt)...", processId))
                .doOnSuccess(v -> log.info("processId={} action=getStatusList status=completed listId={}", processId, listId))
                .doOnError(e -> log.warn("processId={} action=getStatusList status=failed listId={} error={}", processId, listId, e.toString()))
                .map(jwt -> ResponseEntity.ok().contentType(VC_JWT).body(jwt));
    }

    @PostMapping("/revoke")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> revokeCredential(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
            @RequestBody RevokeCredentialRequest request
    ) {
        String processId = UUID.randomUUID().toString();

        return revocationService.revoke(processId, bearerToken, request.procedureId(), request.listId())
                .doFirst(() -> log.info("Process ID: {} - Revoking Credential...", processId))
                .doOnSuccess(v -> log.info("Process ID: {} - Credential revoked successfully.", processId))
                .doOnError(e -> log.warn("Process ID: {} - Revoking credential failed: {}", processId, e.toString()));
    }
}
