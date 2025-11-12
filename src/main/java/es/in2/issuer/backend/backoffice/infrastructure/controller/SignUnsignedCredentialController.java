package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/backoffice/v1/retry-sign-credential")
@RequiredArgsConstructor
public class SignUnsignedCredentialController {

    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final AccessTokenService accessTokenService;

    @PostMapping(value = "/{procedure_id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> signUnsignedCredential(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("procedure_id") String procedureId) {

        return Mono.zip(
                    accessTokenService.getCleanBearerToken(authorizationHeader),
                    accessTokenService.getMandateeEmail(authorizationHeader),
                    accessTokenService.getOrganizationId(authorizationHeader)
                )
                .flatMap(tuple3 -> {
                    String token = tuple3.getT1();
                    String email = tuple3.getT2();
                    String orgId = tuple3.getT3();
                    return credentialSignerWorkflow.retrySignUnsignedCredential(
                            token,
                            procedureId,
                            email,
                            orgId
                    );
                });
    }
}
