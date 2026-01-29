package es.in2.issuer.backend.statusList.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.statusList.application.policies.StatusListPdpService;
import es.in2.issuer.backend.statusList.domain.exception.CredentialDecodedInvalidJsonException;
import es.in2.issuer.backend.statusList.domain.exception.CredentialStatusMissingException;
import es.in2.issuer.backend.statusList.domain.spi.StatusListProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import es.in2.issuer.backend.credentialstatus.domain.service.LegacyCredentialStatusRevocationService;


import static es.in2.issuer.backend.statusList.domain.util.Constants.BITSTRING_ENTRY_TYPE;
import static java.util.Objects.requireNonNull;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevocationWorkflow {

    private static final String REVOKED = "REVOKED";

    private final StatusListProvider statusListProvider;
    private final AccessTokenService accessTokenService;
    private final StatusListPdpService statusListPdpService;
    private final CredentialProcedureService credentialProcedureService;
    private final ObjectMapper objectMapper;
    private final EmailService emailService;
    private final LegacyCredentialStatusRevocationService legacyCredentialStatusRevocationService;

    private record RevocationContext(String token, CredentialProcedure procedure) { }

    public Mono<Void> revoke(String processId, String bearerToken, String credentialProcedureId, int listId) {
        requireNonNull(processId, "processId cannot be null");
        requireNonNull(bearerToken, "bearerToken cannot be null");
        requireNonNull(credentialProcedureId, "credentialProcedureId cannot be null");

        return accessTokenService.getCleanBearerToken(bearerToken)
                .doFirst(() -> log.info(
                        "processId={} action=revokeCredential status=started procedureId={} listId={}",
                        processId, credentialProcedureId, listId
                ))
                .flatMap(token ->
                        credentialProcedureService.getCredentialProcedureById(credentialProcedureId)
                                .doOnSuccess(p -> log.debug(
                                        "processId={} action=revokeCredential step=procedureLoaded procedureId={} credentialStatus={}",
                                        processId, credentialProcedureId, p != null ? p.getCredentialStatus() : null
                                ))
                                .flatMap(procedure ->
                                        statusListPdpService.validateRevokeCredential(processId, token, procedure)
                                                .doOnSuccess(v -> log.info(
                                                        "processId={} action=revokeCredential step=authorizationValidated procedureId={}",
                                                        processId, credentialProcedureId
                                                ))
                                                .thenReturn(new RevocationContext(token, procedure))
                                )
                )
                .flatMap(ctx -> {
                    CredentialStatus credentialStatus = parseCredentialStatus(processId, credentialProcedureId, ctx.procedure.getCredentialDecoded());

                    return routeRevocation(processId, credentialProcedureId, listId, credentialStatus, ctx.token)
                            .then(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(ctx.procedure)
                                    .doOnSuccess(v -> log.info(
                                            "processId={} action=revokeCredential step=procedureUpdated procedureId={}",
                                            processId, credentialProcedureId
                                    ))
                            )
                            .then(emailService.notifyIfCredentialStatusChanges(ctx.procedure, REVOKED)
                                    .doOnSuccess(v -> log.debug(
                                            "processId={} action=revokeCredential step=emailNotificationTriggered procedureId={} newStatus={}",
                                            processId, credentialProcedureId, REVOKED
                                    ))
                            );
                })
                .doOnSuccess(v -> log.info(
                        "processId={} action=revokeCredential status=completed procedureId={} listId={}",
                        processId, credentialProcedureId, listId
                ))
                .doOnError(e -> log.warn(
                        "processId={} action=revokeCredential status=failed procedureId={} listId={} error={}",
                        processId, credentialProcedureId, listId, e.toString()
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
        requireNonNull(decodedCredential, "decodedCredential cannot be null");

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

