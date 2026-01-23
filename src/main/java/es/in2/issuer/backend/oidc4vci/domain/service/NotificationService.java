package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import reactor.core.publisher.Mono;

public interface NotificationService{
    Mono<Void> handleNotification(String processId, String bearerToken, NotificationRequest request);
}
