package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.VerifiableCredentialResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/credential")
@RequiredArgsConstructor
public class CredentialController {

    private final CredentialIssuanceWorkflow credentialIssuanceWorkflow;

    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<VerifiableCredentialResponse>> createVerifiableCredential(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestBody CredentialRequest credentialRequest) {
        String processId = UUID.randomUUID().toString();

        return credentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, authorizationHeader)
                .map(verifiableCredentialResponse -> {
                    if (verifiableCredentialResponse.transactionId() != null) {
                        return ResponseEntity.status(HttpStatus.ACCEPTED).body(verifiableCredentialResponse);
                    } else {
                        return ResponseEntity.status(HttpStatus.OK).body(verifiableCredentialResponse);
                    }
                })
                .doOnSuccess(result ->
                        log.info("VerifiableCredentialController - createVerifiableCredential(): {}", result.toString()));
    }
}
