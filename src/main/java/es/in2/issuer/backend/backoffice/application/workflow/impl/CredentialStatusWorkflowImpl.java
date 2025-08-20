package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.CredentialStatusWorkflow;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusAuthorizationService;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import es.in2.issuer.backend.backoffice.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialStatusWorkflowImpl implements CredentialStatusWorkflow {

    private final CredentialStatusService credentialStatusService;
    private final AccessTokenService accessTokenService;
    private final CredentialStatusAuthorizationService credentialStatusAuthorizationService;
    private final CredentialProcedureService credentialProcedureService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Override
    public Flux<String> getCredentialsByListId(String processId, int listId) {
        return credentialStatusService.getCredentialsByListId(listId)
                .doFirst(() -> log.debug("Process ID: {} - Getting Credentials Status...", processId))
                .doOnComplete(() -> log.debug(
                        "Process ID: {} - All Credential Status retrieved successfully.",
                        processId));
    }

    @Override
    public Mono<Void> revokeCredential(String processId, String bearerToken, String credentialId, int listId) {
        return accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token -> credentialStatusAuthorizationService.authorize(processId, token, credentialId)
                        .then(credentialProcedureService.getCredentialByCredentialId(credentialId))
                )
                .flatMap(credential -> validateStatus(credential.getCredentialStatus())
                        .thenReturn(credential)
                )
                .flatMap(credential -> Mono.just(credential.getCredentialDecoded())
                .flatMap(decodedCredential -> {
                    CredentialStatus credentialStatus = learCredentialEmployeeFactory
                            .mapStringToLEARCredentialEmployee(decodedCredential)
                            .credentialStatus();
                    return revokeAndUpdateCredentialStatus(credential, processId, credentialId, listId, credentialStatus);
                }));

    }

    private Mono<Void> revokeAndUpdateCredentialStatus(CredentialProcedure credentialProcedure, String processId, String credentialId, int listId, CredentialStatus credentialStatus) {
        return credentialStatusService.revokeCredential(listId, credentialStatus)
                .then(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(credentialProcedure))
                .doFirst(() -> log.debug(
                        "Process ID: {} - Revoking Credential with ID: {}",
                        processId,
                        credentialId))
                .doOnSuccess(aVoid -> log.debug(
                        "Process ID: {} - Credential with ID: {} revoked successfully.",
                        processId,
                        credentialId));
    }

    private Mono<Void> validateStatus(CredentialStatusEnum credentialStatus) {
        if (credentialStatus.equals(CredentialStatusEnum.VALID)) {
            return Mono.empty();
        } else {
            return Mono.error(new InvalidStatusException(
                    "Invalid status: " + credentialStatus));
        }
    }
}