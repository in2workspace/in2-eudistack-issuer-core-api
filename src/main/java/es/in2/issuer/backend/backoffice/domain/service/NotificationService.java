package es.in2.issuer.backend.backoffice.domain.service;

import reactor.core.publisher.Mono;

public interface NotificationService {
    Mono<Void> sendNotification(String processId,String procedureId, String organizationId);
}
