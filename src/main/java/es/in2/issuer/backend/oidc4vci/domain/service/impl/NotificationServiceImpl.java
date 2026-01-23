package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.application.workflow.CredentialStatusWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.NotificationService;
import es.in2.issuer.backend.shared.domain.exception.InvalidNotificationIdException;
import es.in2.issuer.backend.shared.domain.exception.InvalidNotificationRequestException;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;


@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements NotificationService {

    private final CredentialProcedureService credentialProcedureService;
    private final CredentialStatusWorkflow credentialStatusWorkflow;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> handleNotification(String processId, String bearerToken, NotificationRequest request) {
        return Mono.defer(() -> {
            try {
                validateRequestDefensively(request);
            } catch (InvalidNotificationRequestException e) {
                log.warn("AUDIT notification_rejected errorCode=invalid_notification_request errorDescription={} notificationId={} event={}",
                        e.getMessage(),
                        (request.notificationId()),
                        (request.event())
                );
                return Mono.error(e);
            }

            final String notificationId = request.notificationId();
            final NotificationEvent event = request.event(); //TODO: gestionar error para event no soportado
            final String eventDescription = request.eventDescription();

            log.info("AUDIT notification_received notificationId={} event={} eventDescription={}",
                    notificationId, event, eventDescription
            );

            return credentialProcedureService.getCredentialProcedureByNotificationId(notificationId)
                    .switchIfEmpty(Mono.defer(() -> {
                        log.warn("AUDIT notification_rejected errorCode=invalid_notification_id errorDescription={} notificationId={} event={}",
                                "The notification_id is not recognized",
                                notificationId,
                                event
                        );
                        return Mono.error(new InvalidNotificationIdException(
                                "The notification_id is not recognized: " + notificationId
                        ));
                    }))
                    .flatMap(procedure -> applyIdempotentUpdate(procedure, event, eventDescription, bearerToken))
                    .then();
        });
    }

    //Revisar si es correcto / repetido en servicio
    private void validateRequestDefensively(NotificationRequest request) {
        if (request == null) {
            throw new InvalidNotificationRequestException("Request body is required");
        }
        if (request.notificationId() == null || request.notificationId().isBlank()) {
            throw new InvalidNotificationRequestException("notification_id is required");
        }
        if (request.event() == null) {
            throw new InvalidNotificationRequestException("event is required");
        }
    }

    private Mono<Void> applyIdempotentUpdate(CredentialProcedure credentialProcedure,NotificationEvent event,String bearerToken,String processId) {

        final CredentialStatusEnum before = credentialProcedure.getCredentialStatus();
        final CredentialStatusEnum after = mapEventToCredentialStatus(event);
        final boolean idempotent = (before == after);

        log.info("AUDIT notification_processing credentialProcedureId={} notificationId={} event={} idempotent={} statusBefore={} statusAfter={}",
                credentialProcedure.getProcedureId(),
                credentialProcedure.getNotificationId(),
                event,
                idempotent,
                before,
                after
        );

        if (idempotent) {
            log.info("AUDIT notification_idempotent credentialProcedureId={} notificationId={} event={} status={}",
                    credentialProcedure.getProcedureId(),
                    credentialProcedure.getNotificationId(),
                    event,
                    before
            );
            return Mono.empty();
        }

        // TODO: Que pasa en caso de error?
        if (event != NotificationEvent.CREDENTIAL_DELETED) {
            log.info("AUDIT notification_no_external_action processId={} credentialProcedureId={} notificationId={} event={}",
                    processId, credentialProcedure.getProcedureId(), credentialProcedure.getNotificationId(), event
            );
            return Mono.empty();
        }

        return revokeCredentialFromDecoded(processId, bearerToken, credentialProcedure);
    }


    private CredentialStatusEnum mapEventToCredentialStatus(NotificationEvent event) {
        return switch (event) {
            case CREDENTIAL_ACCEPTED -> CredentialStatusEnum.VALID;
            case CREDENTIAL_FAILURE -> CredentialStatusEnum.DRAFT; //TODO: revisar estado adecuado
            case CREDENTIAL_DELETED -> CredentialStatusEnum.REVOKED;
        };
    }

    private Mono<Void> revokeCredentialFromDecoded(String processId, String bearerToken,CredentialProcedure procedure) {

        return Mono.fromCallable(() -> {
                    JsonNode credential = objectMapper.readTree(procedure.getCredentialDecoded());

                    JsonNode statusNode = credential.has(VC)
                            ? credential.path(VC).path(CREDENTIAL_STATUS)
                            : credential.path(CREDENTIAL_STATUS);

                    if (statusNode.isMissingNode() || statusNode.isNull()) {
                        throw new IllegalArgumentException("Credential status node not found in decoded credential");
                    }

                    return extractListId(statusNode);
                })
                .flatMap(listId -> credentialStatusWorkflow.revokeCredential(
                                        processId,
                                        bearerToken,
                                        procedure.getProcedureId().toString(),
                                        listId
                                )
                                .doFirst(() -> log.info("Process ID: {} - Revoking Credential... procedureId={} listId={}",
                                        processId, procedure.getProcedureId(), listId))
                                .doOnSuccess(result -> log.info("Process ID: {} - Credential revoked successfully. procedureId={} listId={}",
                                        processId, procedure.getProcedureId(), listId))
                                .then()
                )
                .doOnError(e -> log.warn("Process ID: {} - revokeCredentialFromDecoded failed: {}", processId, e.getMessage(), e));
    }

    private Integer extractListId(JsonNode statusNode) {
        JsonNode slcNode = statusNode.path(STATUS_LIST_CREDENTIAL);
        String slc = slcNode.asText();

        char lastChar = slc.charAt(slc.length() - 1);
        if (!Character.isDigit(lastChar)) {
            throw new IllegalArgumentException("Last character of status_list_credential is not a digit: " + slc);
        }

        return Character.getNumericValue(lastChar);
    }



}
