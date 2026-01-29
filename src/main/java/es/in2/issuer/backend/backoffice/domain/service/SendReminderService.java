package es.in2.issuer.backend.backoffice.domain.service;

import reactor.core.publisher.Mono;

public interface SendReminderService {
    Mono<Void> sendReminder(String processId,String procedureId, String token);
}
