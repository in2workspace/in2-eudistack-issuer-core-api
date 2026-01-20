package es.in2.issuer.backend.statusList.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialStatusResponse;
import es.in2.issuer.backend.backoffice.domain.model.dtos.RevokeCredentialRequest;
import es.in2.issuer.backend.credentialStatus.domain.service.LegacyCredentialStatusQuery;
import es.in2.issuer.backend.statusList.application.RevocationService;
import es.in2.issuer.backend.statusList.application.StatusListService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.relational.core.sql.Not;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

@Slf4j
@RestController
@RequestMapping("/api/v1/status-list")
public class StatusListController {

    private static final MediaType VC_JWT = MediaType.parseMediaType("application/vc+jwt");

    private final StatusListService statusListService;
    private final LegacyCredentialStatusQuery legacyQuery;
    private final RevocationService revocationService;

    public StatusListController(
            StatusListService statusListService,
            LegacyCredentialStatusQuery legacyQuery,
            RevocationService revocationService
    ) {
        this.statusListService = requireNonNull(statusListService, "statusListService cannot be null");
        this.legacyQuery = requireNonNull(legacyQuery, "legacyQuery cannot be null");
        this.revocationService = requireNonNull(revocationService, "revocationService cannot be null");
    }

    /**
     * GET /api/v1/status-list/{listId}
     *
     * Content negotiation rules (matching the previous behavior):
     * - If Accept is missing/blank => default to vc+jwt
     * - If Accept includes * => default to vc+jwt
     * - If Accept includes application/vc+jwt => vc+jwt
     * - If Accept includes application/json   => legacy JSON
     * - Otherwise => 406 Not Acceptable
     */
    @GetMapping("/{listId}")
    public Mono<ResponseEntity<?>> getStatusList(
            @PathVariable Long listId,
            @RequestHeader(value = HttpHeaders.ACCEPT, required = false) String acceptHeader
    ) {
        String processId = UUID.randomUUID().toString();

        if (acceptHeader == null || acceptHeader.isBlank()) {
            return statusListService.getSignedStatusListCredential(listId)
                    .doFirst(() -> log.info("Process ID: {} - Getting Status List Credential (default vc+jwt, no Accept)...", processId))
                    .map(jwt -> ResponseEntity.ok().contentType(VC_JWT).body(jwt));
        }

        List<MediaType> accepted = MediaType.parseMediaTypes(acceptHeader);
        MediaType.sortBySpecificityAndQuality(accepted);

        boolean wantsVcJwt = accepted.stream().anyMatch(mt -> mt.isCompatibleWith(VC_JWT));
        if (wantsVcJwt) {
            return statusListService.getSignedStatusListCredential(listId)
                    .doFirst(() -> log.info("Process ID: {} - Getting Status List Credential (vc+jwt)...", processId))
                    .map(jwt -> ResponseEntity.ok().contentType(VC_JWT).body(jwt));
        }

        boolean wantsJson = accepted.stream().anyMatch(mt -> mt.isCompatibleWith(MediaType.APPLICATION_JSON));
        if (wantsJson) {
            return legacyQuery.getNoncesByListId(Math.toIntExact(listId))
                    .doFirst(() -> log.info("Process ID: {} - Getting Legacy Status List (json)...", processId))
                    .map(CredentialStatusResponse::new)
                    .collectList()
                    .map(list -> ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(list));
        }

        boolean hasWildcard = accepted.stream().anyMatch(mt -> mt.isWildcardType() || mt.isWildcardSubtype());
        if (hasWildcard) {
            return statusListService.getSignedStatusListCredential(listId)
                    .doFirst(() -> log.info("Process ID: {} - Getting Status List Credential (default vc+jwt, */*)...", processId))
                    .map(jwt -> ResponseEntity.ok().contentType(VC_JWT).body(jwt));
        }

        return Mono.just(ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).build());
    }

    @PostMapping("/revoke")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> revokeCredential(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
            @RequestBody RevokeCredentialRequest request
    ) {
        String processId = UUID.randomUUID().toString();

        return revocationService.revoke(processId, bearerToken, request.procedureId(), request.listId())
                .doFirst(() -> log.info("Process ID: {} - Revoking Credential...", processId))
                .doOnSuccess(v -> log.info("Process ID: {} - Credential revoked successfully.", processId));
    }
}
