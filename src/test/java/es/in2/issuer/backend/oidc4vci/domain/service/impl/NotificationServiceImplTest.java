package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.application.workflow.CredentialStatusWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationIdException;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationRequestException;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationServiceImplTest {

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private CredentialStatusWorkflow credentialStatusWorkflow;

    private NotificationServiceImpl notificationServiceImpl;

    @BeforeEach
    void setUp() {
        notificationServiceImpl = new NotificationServiceImpl(
                credentialProcedureService,
                credentialStatusWorkflow,
                new ObjectMapper()
        );
    }

    @Test
    void handleNotification_whenRequestIsNull_shouldErrorInvalidNotificationRequestException() {
        // given
        String processId = "p1";
        String bearer = "token";

        // when
        Mono<Void> result = notificationServiceImpl.handleNotification(processId, bearer, null);

        // then
        StepVerifier.create(result)
                .expectError(InvalidNotificationRequestException.class)
                .verify();

        verifyNoInteractions(credentialProcedureService, credentialStatusWorkflow);
    }

    @Test
    void handleNotification_whenNotificationIdBlank_shouldErrorInvalidNotificationRequestException() {
        // given
        NotificationRequest request = mock(NotificationRequest.class);
        when(request.notificationId()).thenReturn("   ");
        when(request.event()).thenReturn(NotificationEvent.CREDENTIAL_FAILURE);

        // when
        Mono<Void> result = notificationServiceImpl.handleNotification("p1", "token", request);

        // then
        StepVerifier.create(result)
                .expectError(InvalidNotificationRequestException.class)
                .verify();

        verifyNoInteractions(credentialProcedureService, credentialStatusWorkflow);
    }

    @Test
    void handleNotification_whenNotificationIdNotRecognized_shouldErrorInvalidNotificationIdException() {
        // given
        NotificationRequest request = mock(NotificationRequest.class);
        when(request.notificationId()).thenReturn("nid-404");
        when(request.event()).thenReturn(NotificationEvent.CREDENTIAL_FAILURE);
        when(request.eventDescription()).thenReturn("desc");

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-404"))
                .thenReturn(Mono.empty());

        // when
        Mono<Void> result = notificationServiceImpl.handleNotification("p1", "token", request);

        // then
        StepVerifier.create(result)
                .expectError(InvalidNotificationIdException.class)
                .verify();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId("nid-404");
        verifyNoMoreInteractions(credentialProcedureService);
        verifyNoInteractions(credentialStatusWorkflow);
    }

    @Test
    void handleNotification_whenIdempotent_shouldComplete_andNotCallAnyUpdate() {
        NotificationRequest request = mock(NotificationRequest.class);
        when(request.notificationId()).thenReturn("nid-1");
        when(request.event()).thenReturn(NotificationEvent.CREDENTIAL_FAILURE);
        when(request.eventDescription()).thenReturn("desc");

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.ISSUED);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        // when
        Mono<Void> result = notificationServiceImpl.handleNotification("p1", "token", request);

        // then
        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId("nid-1");
        verify(credentialProcedureService, never()).updateCredentialProcedureCredentialStatusToIssued(any());
        verifyNoInteractions(credentialStatusWorkflow);
        verifyNoMoreInteractions(credentialProcedureService);
    }

    @Test
    void handleNotification_whenEventCredentialAccepted_shouldComplete_andNoExternalAction() {
        NotificationRequest request = mock(NotificationRequest.class);
        when(request.notificationId()).thenReturn("nid-2");
        when(request.event()).thenReturn(NotificationEvent.CREDENTIAL_ACCEPTED);
        when(request.eventDescription()).thenReturn("accepted");

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.ISSUED);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-2"))
                .thenReturn(Mono.just(procedure));

        // when
        Mono<Void> result = notificationServiceImpl.handleNotification("p1", "token", request);

        // then
        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId("nid-2");
        verify(credentialProcedureService, never()).updateCredentialProcedureCredentialStatusToIssued(any());
        verifyNoInteractions(credentialStatusWorkflow);
        verifyNoMoreInteractions(credentialProcedureService);
    }

    @Test
    void handleNotification_whenEventCredentialFailureAndNotIdempotent_shouldUpdateToIssued() {
        NotificationRequest request = mock(NotificationRequest.class);
        when(request.notificationId()).thenReturn("nid-3");
        when(request.event()).thenReturn(NotificationEvent.CREDENTIAL_FAILURE);
        when(request.eventDescription()).thenReturn("fail");

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-3"))
                .thenReturn(Mono.just(procedure));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToIssued(procedure))
                .thenReturn(Mono.empty());

        // when
        Mono<Void> result = notificationServiceImpl.handleNotification("p1", "token", request);

        // then
        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId("nid-3");
        verify(credentialProcedureService).updateCredentialProcedureCredentialStatusToIssued(procedure);
        verifyNoInteractions(credentialStatusWorkflow);
        verifyNoMoreInteractions(credentialProcedureService);
    }

    @Test
    void handleNotification_whenEventCredentialDeleted_shouldRevokeCredentialUsingListIdFromDecoded() {
        // given
        String processId = "process-9";
        UUID notificationId = UUID.randomUUID();
        NotificationRequest request = mock(NotificationRequest.class);
        when(request.notificationId()).thenReturn(notificationId.toString());
        when(request.event()).thenReturn(NotificationEvent.CREDENTIAL_DELETED);
        when(request.eventDescription()).thenReturn("deleted");

        UUID procedureId = UUID.randomUUID();
        String decoded = """
                {
                  "vc": {
                    "credentialStatus": {
                      "statusListCredential": "https://example.com/status/list/7"
                    }
                  }
                }
                """;

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(procedure.getProcedureId()).thenReturn(procedureId);
        when(procedure.getNotificationId()).thenReturn(notificationId);
        when(procedure.getCredentialDecoded()).thenReturn(decoded);

        when(credentialProcedureService.getCredentialProcedureByNotificationId(notificationId.toString()))
                .thenReturn(Mono.just(procedure));

        when(credentialStatusWorkflow.revokeCredentialSystem(eq(processId), eq(procedureId.toString()), eq(7)))
                .thenReturn(Mono.empty());

        Mono<Void> result = notificationServiceImpl.handleNotification(processId, "token", request);

        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId(notificationId.toString());

        ArgumentCaptor<String> procIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Integer> listIdCaptor = ArgumentCaptor.forClass(Integer.class);

        verify(credentialStatusWorkflow).revokeCredentialSystem(
                eq(processId),
                procIdCaptor.capture(),
                listIdCaptor.capture()
        );

        assertNotNull(procIdCaptor.getValue());
        assertFalse(procIdCaptor.getValue().isBlank());
        assertNotNull(UUID.fromString(procIdCaptor.getValue()));

        Integer capturedListId = listIdCaptor.getValue();
        assertNotNull(capturedListId);
        assertTrue(capturedListId >= 0);

        verifyNoMoreInteractions(credentialProcedureService, credentialStatusWorkflow);
    }
}
