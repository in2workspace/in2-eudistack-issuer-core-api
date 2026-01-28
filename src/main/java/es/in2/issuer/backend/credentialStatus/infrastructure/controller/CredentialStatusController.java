package es.in2.issuer.backend.credentialStatus.infrastructure.controller;

import es.in2.issuer.backend.credentialStatus.domain.model.entities.dto.CredentialStatusResponse;
import es.in2.issuer.backend.credentialStatus.domain.service.LegacyCredentialStatusQuery;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;

import java.util.UUID;


// Legacy endpoint used to handle credentials with a PlainListEntry credentialStatus.
// This endpoint can be removed once the last credential of this type expires in DOME.

@Slf4j
@RestController
@RequestMapping("/backoffice/v1/credentials/status")
@RequiredArgsConstructor
public class CredentialStatusController {


    private final LegacyCredentialStatusQuery legacyQuery;

    @GetMapping("/{listId}")
    @ResponseStatus(HttpStatus.OK)
    public Flux<CredentialStatusResponse> getCredentialsByListId(@PathVariable int listId) {
        String processId = UUID.randomUUID().toString();

        return legacyQuery.getNoncesByListId(processId, listId)
                .doFirst(() -> log.info("Process ID: {} - Getting Credentials...", processId))
                .map(CredentialStatusResponse::new)
                .doOnComplete(() -> log.info(
                        "Process ID: {} - All Credential retrieved successfully.",
                        processId));

    }
}
