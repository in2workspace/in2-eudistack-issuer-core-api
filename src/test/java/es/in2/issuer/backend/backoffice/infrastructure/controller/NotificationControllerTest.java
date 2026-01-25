package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.service.NotificationService2;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationControllerTest {

    @Mock
    private NotificationService2 notificationService;

    @InjectMocks
    private NotificationController2 notificationController;

    @Test
    void sendEmailNotification_completesSuccessfully() {
        // Arrange
        String authorizationHeader = "Bearer some.jwt.token";
        String procedureId = "testProcedureId";

        when(notificationService.sendNotification(anyString(), eq(procedureId), eq(authorizationHeader)))
                .thenReturn(Mono.empty());

        // Act
        Mono<Void> result = notificationController.sendEmailNotification(authorizationHeader, procedureId);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();

        verify(notificationService).sendNotification(anyString(), eq(procedureId), eq(authorizationHeader));
    }
}
