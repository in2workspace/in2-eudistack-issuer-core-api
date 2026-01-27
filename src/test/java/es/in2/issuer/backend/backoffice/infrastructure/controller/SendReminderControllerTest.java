package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.domain.service.SendReminderService;
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
class SendReminderControllerTest {

    @Mock
    private SendReminderService sendReminderService;

    @InjectMocks
    private SendReminderController sendReminderController;

    @Test
    void sendEmailNotification_completesSuccessfully() {
        // Arrange
        String authorizationHeader = "Bearer some.jwt.token";
        String procedureId = "testProcedureId";

        when(sendReminderService.sendReminder(anyString(), eq(procedureId), eq(authorizationHeader)))
                .thenReturn(Mono.empty());

        // Act
        Mono<Void> result = sendReminderController.sendEmailReminder(authorizationHeader, procedureId);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();

        verify(sendReminderService).sendReminder(anyString(), eq(procedureId), eq(authorizationHeader));
    }
}
