package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.statusList.application.RevocationWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CREDENTIAL_STATUS;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.STATUS_LIST_CREDENTIAL;
import static es.in2.issuer.backend.shared.domain.util.Constants.VC;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationServiceImplTest {

    @InjectMocks
    private NotificationServiceImpl notificationService;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private RevocationWorkflow revocationWorkflow;

    private final String processId = "proc-123";
    private final String bearerToken = "Bearer token";

    private UUID procedureId;
    private CredentialProcedure procedure;

    @BeforeEach
    void setUp() {
        procedureId = UUID.randomUUID();
        UUID notificationId = UUID.randomUUID();
        procedure = mock(CredentialProcedure.class);


        when(procedure.getProcedureId()).thenReturn(procedureId);
        when(procedure.getNotificationId()).thenReturn(notificationId);
    }

    @Test
    void handleNotification_idempotent_shouldDoNothing_andNotRevoke() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(notificationService.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId("nid-1");
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_nonDeletedEvent_shouldNotRevoke_evenIfNotIdempotent() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_ACCEPTED, "desc");

        StepVerifier.create(notificationService.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(credentialProcedureService).getCredentialProcedureByNotificationId("nid-1");
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_deletedEvent_shouldRevoke_whenNotIdempotent_andVcWrappedJson() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);

        String decoded = """
                {
                  "%s": {
                    "%s": {
                      "%s": "https://example/status/7"
                    }
                  }
                }
                """.formatted(VC, CREDENTIAL_STATUS, STATUS_LIST_CREDENTIAL);

        when(procedure.getCredentialDecoded()).thenReturn(decoded);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        when(revocationWorkflow.revokeSystem(processId, bearerToken, procedureId.toString(), 7))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(notificationService.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(revocationWorkflow).revokeSystem(processId, bearerToken, procedureId.toString(), 7);
    }

    @Test
    void handleNotification_deletedEvent_shouldRevoke_whenNotIdempotent_andRootJson() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);

        String decoded = """
                {
                  "%s": {
                    "%s": "https://example/status/3"
                  }
                }
                """.formatted(CREDENTIAL_STATUS, STATUS_LIST_CREDENTIAL);

        when(procedure.getCredentialDecoded()).thenReturn(decoded);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        when(revocationWorkflow.revokeSystem(processId, bearerToken, procedureId.toString(),3))
                .thenReturn(Mono.empty());

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(notificationService.handleNotification(processId, request, bearerToken))
                .verifyComplete();

        verify(revocationWorkflow).revokeSystem(processId, bearerToken, procedureId.toString(), 3);
    }

    @Test
    void handleNotification_deletedEvent_statusListCredentialBlank_shouldError() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);

        String decoded = """
                {
                  "%s": {
                    "%s": {
                      "%s": "   "
                    }
                  }
                }
                """.formatted(VC, CREDENTIAL_STATUS, STATUS_LIST_CREDENTIAL);

        when(procedure.getCredentialDecoded()).thenReturn(decoded);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(notificationService.handleNotification(processId, request, bearerToken))
                .expectErrorSatisfies(ex -> {
                    assert ex instanceof IllegalArgumentException;
                    assert ex.getMessage().contains("status_list_credential is missing/blank");
                })
                .verify();

        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void handleNotification_deletedEvent_lastCharNotDigit_shouldError() {
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);

        String decoded = """
                {
                  "%s": {
                    "%s": {
                      "%s": "https://example/status/X"
                    }
                  }
                }
                """.formatted(VC, CREDENTIAL_STATUS, STATUS_LIST_CREDENTIAL);

        when(procedure.getCredentialDecoded()).thenReturn(decoded);

        when(credentialProcedureService.getCredentialProcedureByNotificationId("nid-1"))
                .thenReturn(Mono.just(procedure));

        NotificationRequest request = new NotificationRequest("nid-1", NotificationEvent.CREDENTIAL_DELETED, "desc");

        StepVerifier.create(notificationService.handleNotification(processId, request, bearerToken))
                .expectErrorSatisfies(ex -> {
                    assert ex instanceof IllegalArgumentException;
                    assert ex.getMessage().contains("not a digit");
                })
                .verify();

        verifyNoInteractions(revocationWorkflow);
    }
}
