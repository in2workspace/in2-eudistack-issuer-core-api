package es.in2.issuer.backend.backoffice.domain.service;

import reactor.core.publisher.Mono;

public interface NotificationService2 {
    Mono<Void> sendNotification(String processId,String procedureId, String token);
}
