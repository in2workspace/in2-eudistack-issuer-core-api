package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.service.NotificationService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class NotificationControllerTest {

    @Mock
    private NotificationService notificationService;

    @Mock
    private AccessTokenService accessTokenService;

    @InjectMocks
    private NotificationController notificationController;

    @Test
    void sendEmailNotification_completesSuccessfully() {
        // Arrange
        String authorizationHeader = "Bearer some.jwt.token";
        String procedureId = "testProcedureId";
        String organizationId = "org-123";

        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));

       when(notificationService.sendNotification(anyString(), eq(procedureId), eq(organizationId)))
                .thenReturn(Mono.empty());

        // Act
        Mono<Void> result = notificationController.sendEmailNotification(authorizationHeader, procedureId);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
        verify(notificationService).sendNotification(anyString(), eq(procedureId), eq(organizationId));
    }
}
