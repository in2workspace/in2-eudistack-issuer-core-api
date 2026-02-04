package es.in2.issuer.backend.statuslist.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.statuslist.domain.service.LegacyCredentialStatusRevocationService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.statuslist.application.policies.StatusListPdpService;
import es.in2.issuer.backend.statuslist.domain.exception.CredentialDecodedInvalidJsonException;
import es.in2.issuer.backend.statuslist.domain.exception.CredentialStatusMissingException;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.BITSTRING_ENTRY_TYPE;
import static es.in2.issuer.backend.statuslist.domain.util.Constants.REVOKED;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevocationWorkflow {

    private final StatusListProvider statusListProvider;
    private final AccessTokenService accessTokenService;
    private final StatusListPdpService statusListPdpService;
    private final CredentialProcedureService credentialProcedureService;
    private final ObjectMapper objectMapper;
    private final EmailService emailService;
    private final LegacyCredentialStatusRevocationService legacyCredentialStatusRevocationService;

    private record RevocationContext(String token, CredentialProcedure procedure) { }

    @FunctionalInterface
    private interface RevocationValidator {
        Mono<Void> validate(String processId, String token, CredentialProcedure procedure);
    }

    public Mono<Void> revoke(String processId, String bearerToken, String credentialProcedureId, int listId) {
        return revokeInternal(
                processId,
                bearerToken,
                credentialProcedureId,
                listId,
                statusListPdpService::validateRevokeCredential,
                "revokeCredential"
        );
    }

    public Mono<Void> revokeSystem(String processId, String bearerToken, String credentialProcedureId, int listId) {
        return revokeInternal(
                processId,
                bearerToken,
                credentialProcedureId,
                listId,
                (pid, token, procedure) -> statusListPdpService.validateRevokeCredentialSystem(pid, procedure),
                "revokeSystemCredential"
        );
    }

    private Mono<Void> revokeInternal(
            String processId,
            String bearerToken,
            String credentialProcedureId,
            int listId,
            RevocationValidator validator,
            String action
    ) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(bearerToken, "bearerToken");
        requireNonNullParam(credentialProcedureId, "credentialProcedureId");

        return accessTokenService.getCleanBearerToken(bearerToken)
                .doFirst(() -> log.info(
                        "processId={} action={} status=started procedureId={} listId={}",
                        processId, action, credentialProcedureId, listId
                ))
                .flatMap(token ->
                        credentialProcedureService.getCredentialProcedureById(credentialProcedureId)
                                .doOnSuccess(p -> log.debug(
                                        "processId={} action={} step=procedureLoaded procedureId={} credentialStatus={}",
                                        processId, action, credentialProcedureId, p != null ? p.getCredentialStatus() : null
                                ))
                                .flatMap(procedure ->
                                        validator.validate(processId, token, procedure)
                                                .doOnSuccess(v -> log.info(
                                                        "processId={} action={} step=validationPassed procedureId={}",
                                                        processId, action, credentialProcedureId
                                                ))
                                                .thenReturn(new RevocationContext(token, procedure))
                                )
                )
                .flatMap(ctx -> {
                    CredentialStatus credentialStatus = parseCredentialStatus(
                            processId,
                            credentialProcedureId,
                            ctx.procedure.getCredentialDecoded()
                    );

                    return routeRevocation(processId, credentialProcedureId, listId, credentialStatus, ctx.token)
                            .then(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(ctx.procedure)
                                    .doOnSuccess(v -> log.info(
                                            "processId={} action={} step=procedureUpdated procedureId={}",
                                            processId, action, credentialProcedureId
                                    ))
                            )
                            .then(emailService.notifyIfCredentialStatusChanges(ctx.procedure, REVOKED)
                                    .doOnSuccess(v -> log.debug(
                                            "processId={} action={} step=emailNotificationTriggered procedureId={} newStatus={}",
                                            processId, action, credentialProcedureId, REVOKED
                                    ))
                            );
                })
                .doOnSuccess(v -> log.info(
                        "processId={} action={} status=completed procedureId={} listId={}",
                        processId, action, credentialProcedureId, listId
                ))
                .doOnError(e -> log.warn(
                        "processId={} action={} status=failed procedureId={} listId={} error={}",
                        processId, action, credentialProcedureId, listId, e.toString()
                ));
    }

    private Mono<Void> routeRevocation(
            String processId,
            String procedureId,
            int listId,
            CredentialStatus credentialStatus,
            String token
    ) {
        String type = credentialStatus != null ? credentialStatus.type() : null;

        if (BITSTRING_ENTRY_TYPE.equals(type)) {
            log.info(
                    "processId={} action=revokeCredential step=route selected=bitstring procedureId={}",
                    processId, procedureId
            );
            return statusListProvider.revoke(procedureId, token);
        }

        log.info(
                "processId={} action=revokeCredential step=route selected=legacy procedureId={} listId={}",
                processId, procedureId, listId
        );
        return legacyCredentialStatusRevocationService.revoke(listId, credentialStatus);
    }

    private CredentialStatus parseCredentialStatus(String processId, String procedureId, String decodedCredential) {
        requireNonNullParam(decodedCredential, "decodedCredential");

        try {
            JsonNode root = objectMapper.readTree(decodedCredential);
            JsonNode credentialStatusNode = root.get("credentialStatus");

            if (credentialStatusNode == null || credentialStatusNode.isNull()) {
                log.warn(
                        "processId={} action=revokeCredential step=parseCredentialStatus result=missing procedureId={}",
                        processId, procedureId
                );
                throw new CredentialStatusMissingException(procedureId);
            }

            CredentialStatus credentialStatus = CredentialStatus.builder()
                    .id(textOrNull(credentialStatusNode, "id"))
                    .type(textOrNull(credentialStatusNode, "type"))
                    .statusPurpose(textOrNull(credentialStatusNode, "statusPurpose"))
                    .statusListIndex(textOrNull(credentialStatusNode, "statusListIndex"))
                    .statusListCredential(textOrNull(credentialStatusNode, "statusListCredential"))
                    .build();

            log.debug(
                    "processId={} action=revokeCredential step=parseCredentialStatus result=ok procedureId={} type={} purpose={} index={}",
                    processId, procedureId, credentialStatus.type(), credentialStatus.statusPurpose(), credentialStatus.statusListIndex()
            );

            return credentialStatus;
        } catch (JsonProcessingException e) {
            log.warn(
                    "processId={} action=revokeCredential step=parseCredentialStatus result=invalidJson procedureId={} error={}",
                    processId, procedureId, e.toString()
            );
            throw new CredentialDecodedInvalidJsonException(procedureId, e);
        }
    }

    private String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        return v.asText();
    }
}
