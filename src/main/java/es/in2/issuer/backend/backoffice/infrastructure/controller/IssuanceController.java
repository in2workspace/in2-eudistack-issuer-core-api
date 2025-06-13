package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialRequest;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping
@RequiredArgsConstructor
public class IssuanceController {

    private final CredentialIssuanceWorkflow credentialIssuanceWorkflow;
    private final AccessTokenService accessTokenService;

    @PostMapping("/backoffice/v1/issuances")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> internalIssueCredential(@RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
                                              @RequestBody PreSubmittedCredentialRequest preSubmittedCredentialRequest) {
        String processId = UUID.randomUUID().toString();
        return accessTokenService.getCleanBearerToken(bearerToken).flatMap(
                token -> credentialIssuanceWorkflow.execute(processId, preSubmittedCredentialRequest, token, null));
    }

    @PostMapping("/vci/v1/issuances")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> externalIssueCredential(@RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
                                              @RequestHeader(name = "X-Id-Token", required = false) String idToken,
                                              @RequestBody PreSubmittedCredentialRequest preSubmittedCredentialRequest) {
        String processId = UUID.randomUUID().toString();
        return accessTokenService.getCleanBearerToken(bearerToken).flatMap(
                token -> credentialIssuanceWorkflow.execute(processId, preSubmittedCredentialRequest, token, idToken));
    }

}