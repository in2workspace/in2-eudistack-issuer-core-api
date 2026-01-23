package es.in2.issuer.backend.oidc4vci.domain.service.impl;

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

import java.time.Instant;


@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements NotificationService {

    private final CredentialProcedureService credentialProcedureService;

    @Override
    public Mono<Void> handleNotification(NotificationRequest request) {
        return Mono.defer(() -> {
            validateRequestDefensively(request);

            final String notificationId = request.notificationId();
            final NotificationEvent event = request.event(); //TODO: gestionar error para event no soportado
            final String eventDescription = request.eventDescription();

            return credentialProcedureService.getCredentialProcedureByNotificationId(notificationId)
                    .switchIfEmpty(Mono.error(new InvalidNotificationIdException("The notification_id is not recognized: " + notificationId)))
                    .flatMap(procedure -> applyIdempotentUpdate(procedure, event, eventDescription))
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

    private Mono<Void> applyIdempotentUpdate(CredentialProcedure credentialProcedure,NotificationEvent event,String eventDescription) {
        final Instant now = Instant.now();
        final CredentialStatusEnum targetStatus = mapEventToCredentialStatus(event);

        if (credentialProcedure.getCredentialStatus() == targetStatus) {
            return notificationAuditService
                    .recordIfNeeded(procedure.getProcedureId(), procedure.getNotificationId(), event, eventDescription, now, true)
                    .onErrorResume(e -> {
                        log.warn("Audit record failed on idempotent notification: {}", e.getMessage(), e);
                        return Mono.empty();
                    });
        }

        credentialProcedure.setCredentialStatus(targetStatus); //TODO: revisar servicio cambio de estado
        //TODO: registrar evento para auditoria

        return procedureRepository.save(credentialProcedure)
                .then(notificationAuditService
                        .recordIfNeeded(procedure.getProcedureId(), procedure.getNotificationId(), event, eventDescription, now, false)
                        .onErrorResume(e -> {
                            log.warn("Audit record failed: {}", e.getMessage(), e);
                            return Mono.empty();
                        })
                )
                .then();
    }

    private CredentialStatusEnum mapEventToCredentialStatus(NotificationEvent event) {
        return switch (event) {
            case CREDENTIAL_ACCEPTED -> CredentialStatusEnum.VALID;
            case CREDENTIAL_FAILURE -> CredentialStatusEnum.DRAFT;
            case CREDENTIAL_DELETED -> CredentialStatusEnum.REVOKED;
        };
    }




}
