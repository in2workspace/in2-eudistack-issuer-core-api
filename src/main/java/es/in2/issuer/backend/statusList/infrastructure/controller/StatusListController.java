package es.in2.issuer.backend.statusList.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialStatusResponse;
import es.in2.issuer.backend.backoffice.domain.model.dtos.RevokeCredentialRequest;
import es.in2.issuer.backend.credentialStatus.domain.service.LegacyCredentialStatusQuery;
import es.in2.issuer.backend.statusList.application.RevocationService;
import es.in2.issuer.backend.statusList.application.StatusListService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
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
        this.statusListService = requireNonNull(statusListService);
        this.legacyQuery = requireNonNull(legacyQuery);
        this.revocationService = requireNonNull(revocationService);
    }

    // 1) vc+jwt when requested via Accept (content negotiation)
    @GetMapping(value = "/{listId}", produces = "application/vc+jwt")
    public Mono<ResponseEntity<String>> getVcJwt(@PathVariable Long listId) {
        String processId = UUID.randomUUID().toString();

        return statusListService.getSignedStatusListCredential(listId)
                .doFirst(() -> log.info("Process ID: {} - Getting Status List Credential (vc+jwt)...", processId))
                .map(jwt -> ResponseEntity.ok().contentType(VC_JWT).body(jwt));
    }

    // 2) legacy only when JSON is requested via Accept (content negotiation)
    @GetMapping(value = "/{listId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Flux<CredentialStatusResponse> getLegacy(@PathVariable Long listId) {
        String processId = UUID.randomUUID().toString();

        return legacyQuery.getNoncesByListId(Math.toIntExact(listId))
                .doFirst(() -> log.info("Process ID: {} - Getting Legacy Status List (json)...", processId))
                .map(CredentialStatusResponse::new);
    }

    // 3) default when Accept is missing => vc+jwt
    @GetMapping(value = "/{listId}", headers = "!Accept")
    public Mono<ResponseEntity<String>> getDefaultNoAccept(@PathVariable Long listId) {
        String processId = UUID.randomUUID().toString();

        return statusListService.getSignedStatusListCredential(listId)
                .doFirst(() -> log.info("Process ID: {} - Getting Status List Credential (default vc+jwt)...", processId))
                .map(jwt -> ResponseEntity.ok().contentType(VC_JWT).body(jwt));
    }

    // 4) fallback: Accept present but not acceptable (also handles */* => vc+jwt)
    @GetMapping("/{listId}")
    public Mono<ResponseEntity<?>> fallbackByAccept(
            @PathVariable Long listId,
            @RequestHeader(value = HttpHeaders.ACCEPT, required = false) String acceptHeader
    ) {

        if (acceptHeader == null || acceptHeader.isBlank()) {
            return statusListService.getSignedStatusListCredential(listId)
                    .map(jwt -> ResponseEntity.ok().contentType(VC_JWT).body(jwt));
        }

        List<MediaType> accepted = MediaType.parseMediaTypes(acceptHeader);
        MediaType.sortBySpecificityAndQuality(accepted);

        // Treat */* as default => vc+jwt
        boolean hasWildcard = accepted.stream().anyMatch(MediaType.ALL::includes);
        if (hasWildcard) {
            return statusListService.getSignedStatusListCredential(listId)
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

