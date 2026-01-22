package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/oid4vci/v1")
public class NotificationController {
    @PostMapping("/notification")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> handleNotification(@RequestBody @Valid NotificationRequest request,@RequestHeader("Authorization") String authorization {
        // Validar notification_id
        // Procesar evento
        // Actualizar estado del procedimiento
    }
}
