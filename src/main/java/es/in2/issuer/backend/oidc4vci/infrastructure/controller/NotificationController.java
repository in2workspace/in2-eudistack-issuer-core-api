package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.service.NotificationService;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/notification")
@RequiredArgsConstructor
public class NotificationController {

    private final AccessTokenService accessTokenService;
    private final NotificationService notificationService;

    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> handleNotification(@RequestBody @Valid NotificationRequest request,@RequestHeader("Authorization") String authorization) {
        String processId = UUID.randomUUID().toString();
        return Mono.defer(() -> {
                    log.info("Process ID: {} - Handle notification start", processId);
                    return accessTokenService.getCleanBearerToken(authorization)
                            .flatMap(token -> notificationService.handleNotification(request));
                })
                .doOnSuccess(v ->
                        log.info("Process ID: {} - Handle notification ok", processId)
                )
                .doOnError(e ->
                        log.warn("Process ID: {} - Handle notification failed: {}", processId, e.getMessage(), e)
                );
    }
}
