package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.service.NotificationService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/backoffice/v1/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;
    private final AccessTokenService accessTokenService;

    @PostMapping(value = "/{procedure_id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> sendEmailNotification(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader, @PathVariable("procedure_id") String procedureId) {
        String processId = UUID.randomUUID().toString();
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(organizationId -> notificationService.sendNotification(processId, procedureId, organizationId))
                .doOnTerminate(() -> log.info("NotificationController - sendEmailNotification()"));
    }
}
