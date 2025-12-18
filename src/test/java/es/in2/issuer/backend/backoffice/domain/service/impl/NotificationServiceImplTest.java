package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CREDENTIAL_ACTIVATION_EMAIL_SUBJECT;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.CREDENTIAL_READY;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.DRAFT;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.PEND_DOWNLOAD;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.WITHDRAWN;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationServiceImplTest {

    private final String processId = "processId";
    private final String procedureId = "procedureId";
    private final String bearerToken = "Bearer some.jwt.token";
    private final String cleanToken = "clean-token";

    private final String issuerUiExternalDomain = "https://example.com";
    private final String knowledgebaseWalletUrl = "https://knowledgebaseUrl.com";

    private final String mandateeEmail = "mandatee@example.com";
    private final String organization = "Acme Org";
    private final String transactionCode = "transactionCode123";
    private final String email = "owner@example.com";

    @Mock private AppConfig appConfig;
    @Mock private AccessTokenService accessTokenService;
    @Mock private BackofficePdpService backofficePdpService;
    @Mock private EmailService emailService;
    @Mock private CredentialProcedureService credentialProcedureService;
    @Mock private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @InjectMocks
    private NotificationServiceImpl notificationService;

    @BeforeEach
    void setup() {
        // Common config stubs
        lenient().when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        lenient().when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);

        // Default PDP and token behavior
        lenient().when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));
        lenient().when(backofficePdpService.validateSendReminder(processId, cleanToken, procedureId))
                .thenReturn(Mono.empty());
    }

    @Test
    void sendNotification_whenDraft_sendsActivationEmail() {
        // arrange
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(DRAFT);

        CredentialOfferEmailNotificationInfo emailInfo =
                new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                .thenReturn(Mono.just(emailInfo));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
                .thenReturn(Mono.just(transactionCode));
        when(emailService.sendCredentialActivationEmail(
                mandateeEmail,
                CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
                knowledgebaseWalletUrl,
                organization
        )).thenReturn(Mono.empty());

        // act
        var result = notificationService.sendNotification(processId, procedureId, bearerToken);

        // assert
        StepVerifier.create(result).verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(backofficePdpService).validateSendReminder(processId, cleanToken, procedureId);
        verify(emailService, times(1))
                .sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString());
        verifyNoMoreInteractions(emailService);
    }

    @Test
    void sendNotification_whenWithdrawn_sendsActivationEmail() {
        // arrange
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(WITHDRAWN);

        CredentialOfferEmailNotificationInfo emailInfo =
                new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                .thenReturn(Mono.just(emailInfo));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
                .thenReturn(Mono.just(transactionCode));
        when(emailService.sendCredentialActivationEmail(
                mandateeEmail,
                CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
                knowledgebaseWalletUrl,
                organization
        )).thenReturn(Mono.empty());

        // act
        var result = notificationService.sendNotification(processId, procedureId, bearerToken);

        // assert
        StepVerifier.create(result).verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(backofficePdpService).validateSendReminder(processId, cleanToken, procedureId);
        verify(emailService, times(1))
                .sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString());
        verifyNoMoreInteractions(emailService);
    }

    @Test
    void sendNotification_whenDraft_emailFailure_mapsToEmailCommunicationException() {
        // arrange
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(DRAFT);

        CredentialOfferEmailNotificationInfo emailInfo =
                new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                .thenReturn(Mono.just(emailInfo));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
                .thenReturn(Mono.just(transactionCode));
        when(emailService.sendCredentialActivationEmail(
                anyString(), anyString(), anyString(), anyString(), anyString()
        )).thenReturn(Mono.error(new RuntimeException("boom")));

        // act
        var result = notificationService.sendNotification(processId, procedureId, bearerToken);

        // assert
        StepVerifier.create(result)
                .expectErrorMatches(ex -> ex instanceof EmailCommunicationException &&
                        ex.getMessage().contains(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .verify();
    }

    @Test
    void sendNotification_whenPendDownload_sendsSignedNotification() {
        // arrange
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(PEND_DOWNLOAD);
        when(credentialProcedure.getEmail()).thenReturn(email);

        CredentialOfferEmailNotificationInfo emailInfo =
                new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                .thenReturn(Mono.just(emailInfo));
        when(emailService.sendCredentialSignedNotification(
                email,
                CREDENTIAL_READY,
                "email.you-can-use-wallet")
        ).thenReturn(Mono.empty());

        // act
        var result = notificationService.sendNotification(processId, procedureId, bearerToken);

        // assert
        StepVerifier.create(result).verifyComplete();

        verify(accessTokenService).getCleanBearerToken(bearerToken);
        verify(backofficePdpService).validateSendReminder(processId, cleanToken, procedureId);
        verify(emailService, times(1))
                .sendCredentialSignedNotification(
                        email,
                        CREDENTIAL_READY,
                        "email.you-can-use-wallet"
                );
        verifyNoMoreInteractions(emailService);
    }

    @Test
    void sendNotification_whenPdpDeniesAccess_failsWithAccessDenied() {
        // arrange
        when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));
        when(backofficePdpService.validateSendReminder(processId, cleanToken, procedureId))
                .thenReturn(Mono.error(new AccessDeniedException("not allowed")));

        // Important: avoid .then(null) -> NPE
        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(mock(CredentialProcedure.class)));

        // act
        var result = notificationService.sendNotification(processId, procedureId, bearerToken);

        // assert
        StepVerifier.create(result)
                .expectError(AccessDeniedException.class)
                .verify();

        verifyNoInteractions(emailService);
    }

}
