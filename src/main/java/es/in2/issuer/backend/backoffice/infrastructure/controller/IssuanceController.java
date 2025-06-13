package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedDataCredentialRequest;
import jakarta.validation.Valid;
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

    @PostMapping("/backoffice/v1/issuances")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> internalIssueCredential(@RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
                                              @RequestBody @Valid PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest) {
        String processId = UUID.randomUUID().toString();
        return credentialIssuanceWorkflow.execute(processId, preSubmittedDataCredentialRequest, bearerToken, null);
    }

    @PostMapping("/vci/v1/issuances")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> externalIssueCredential(@RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
                                              @RequestHeader(name = "X-Id-Token", required = false) String idToken,
                                              @RequestBody @Valid PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest) {
        String processId = UUID.randomUUID().toString();
        return credentialIssuanceWorkflow.execute(processId, preSubmittedDataCredentialRequest, bearerToken, idToken);
    }

}