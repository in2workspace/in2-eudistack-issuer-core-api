package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedures;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/backoffice/v1/procedures")
@RequiredArgsConstructor
public class CredentialProcedureController {

    private final CredentialProcedureService credentialProcedureService;
    private final AccessTokenService accessTokenService;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialProcedures> getAllCredentialProcedures(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(credentialProcedureService::getAllProceduresBasicInfoByOrganizationId)
                .doOnNext(result -> log.info("CredentialManagementController - getAllProcedures()"));
    }

    //fixme: change to /{procedure_id}
    @GetMapping(value = "/{procedure_id}/credential-decoded", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialDetails> getCredentialByProcedureId(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
                                                              @PathVariable("procedure_id") String procedureId) {
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(organizationId -> credentialProcedureService.getProcedureDetailByProcedureIdAndOrganizationId(organizationId, procedureId))
                .doOnNext(result -> log.info("CredentialManagementController - getProcedure()"));
    }

}
