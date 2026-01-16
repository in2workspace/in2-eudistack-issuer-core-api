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

import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

@Slf4j
@RestController
@RequestMapping("/api/v1/status-list")
public class StatusListController {


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

    // New / future: Status List Credential (bitstring, signed)
    @GetMapping(value = "/{listId}", produces = "application/vc+jwt")
    public Mono<ResponseEntity<String>> getStatusListCredential(@PathVariable Long listId) {
        return statusListService.getSignedStatusListCredential(listId)
                .map(ResponseEntity::ok);
    }

    // Legacy: list of nonces
    @GetMapping(value = "/{listId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Flux<CredentialStatusResponse> getLegacyStatusList(@PathVariable int listId) {
        return legacyQuery.getNoncesByListId(listId)
                .map(CredentialStatusResponse::new);
    }

    @PostMapping("/revoke")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> revokeCredential(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
            @RequestBody RevokeCredentialRequest request
    ) {
        String processId = UUID.randomUUID().toString();

        return revocationService.revoke(
                        processId,
                        bearerToken,
                        request.procedureId(),
                        request.listId()
                )
                .doFirst(() -> log.info("Process ID: {} - Revoking Credential...", processId))
                .doOnSuccess(v -> log.info("Process ID: {} - Credential revoked successfully.", processId));
    }


}
