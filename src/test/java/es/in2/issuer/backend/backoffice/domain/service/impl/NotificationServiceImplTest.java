package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
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
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.DRAFT;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.PEND_DOWNLOAD;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.WITHDRAWN;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;

@ExtendWith(MockitoExtension.class)
class NotificationServiceImplTest {

    private final String processId = "processId";
    private final String procedureId = "procedureId";
    private final String organizationId = "org-123"; // Provided by controller layer

    private final String issuerUiExternalDomain = "https://example.com";
    private final String knowledgebaseWalletUrl = "https://knowledgebaseUrl.com";

    private final String mandateeEmail = "mandatee@example.com";
    private final String organization = "Acme Org";
    private final String transactionCode = "transactionCode123";
    private final String email = "owner@example.com";

    @Mock private AppConfig appConfig;
    @Mock private EmailService emailService;
    @Mock private CredentialProcedureService credentialProcedureService;
    @Mock private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @InjectMocks
    private NotificationServiceImpl notificationService;

    @BeforeEach
    void setup() {
        lenient().when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        lenient().when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);
    }

    @Test
    void sendNotification_whenDraft_sendsActivationEmail() {
        // Arrange
        CredentialProcedure cp = mock(CredentialProcedure.class);
        when(cp.getCredentialStatus()).thenReturn(DRAFT);
        when(cp.getOrganizationIdentifier()).thenReturn(organizationId); // Must match input org
        // Email info built from the already-fetched entity
        CredentialOfferEmailNotificationInfo emailInfo =
                new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(cp));
        when(credentialProcedureService.buildCredentialOfferEmailInfoFromProcedure(cp))
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

        // Act
        var result = notificationService.sendNotification(processId, procedureId, organizationId);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(emailService, times(1))
                .sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString());
        verifyNoMoreInteractions(emailService);
    }

    @Test
    void sendNotification_whenWithdrawn_sendsActivationEmail() {
        // Arrange
        CredentialProcedure cp = mock(CredentialProcedure.class);
        when(cp.getCredentialStatus()).thenReturn(WITHDRAWN);
        when(cp.getOrganizationIdentifier()).thenReturn(organizationId);

        CredentialOfferEmailNotificationInfo emailInfo =
                new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(cp));
        when(credentialProcedureService.buildCredentialOfferEmailInfoFromProcedure(cp))
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

        // Act
        var result = notificationService.sendNotification(processId, procedureId, organizationId);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(emailService, times(1))
                .sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString());
        verifyNoMoreInteractions(emailService);
    }

    @Test
    void sendNotification_whenDraft_emailFailure_mapsToEmailCommunicationException() {
        // Arrange
        CredentialProcedure cp = mock(CredentialProcedure.class);
        when(cp.getCredentialStatus()).thenReturn(DRAFT);
        when(cp.getOrganizationIdentifier()).thenReturn(organizationId);

        CredentialOfferEmailNotificationInfo emailInfo =
                new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(cp));
        when(credentialProcedureService.buildCredentialOfferEmailInfoFromProcedure(cp))
                .thenReturn(Mono.just(emailInfo));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
                .thenReturn(Mono.just(transactionCode));
        when(emailService.sendCredentialActivationEmail(
                anyString(), anyString(), anyString(), anyString(), anyString()
        )).thenReturn(Mono.error(new RuntimeException("boom")));

        // Act
        var result = notificationService.sendNotification(processId, procedureId, organizationId);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(ex -> ex instanceof EmailCommunicationException &&
                        ex.getMessage().contains(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .verify();
    }

    @Test
    void sendNotification_whenPendDownload_sendsSignedNotification() {
        // Arrange
        CredentialProcedure cp = mock(CredentialProcedure.class);
        when(cp.getCredentialStatus()).thenReturn(PEND_DOWNLOAD);
        when(cp.getEmail()).thenReturn(email);
        when(cp.getOrganizationIdentifier()).thenReturn(organizationId);

        // Even though PEND_DOWNLOAD branch does not use the built info, the code still builds it beforehand
        CredentialOfferEmailNotificationInfo emailInfo =
                new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(cp));
        when(credentialProcedureService.buildCredentialOfferEmailInfoFromProcedure(cp))
                .thenReturn(Mono.just(emailInfo));
        when(emailService.sendCredentialSignedNotification(
                email,
                CREDENTIAL_READY,
                "email.you-can-use-wallet")
        ).thenReturn(Mono.empty());

        // Act
        var result = notificationService.sendNotification(processId, procedureId, organizationId);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(emailService, times(1))
                .sendCredentialSignedNotification(
                        email,
                        CREDENTIAL_READY,
                        "email.you-can-use-wallet"
                );
        verifyNoMoreInteractions(emailService);
    }
}


//    @Test
//    void testSendNotification_DraftStatus() {
//        String transactionCode = "transactionCode";
//        when(credentialProcedureService.getCredentialStatusByProcedureId(procedureId))
//                .thenReturn(Mono.just(CredentialStatus.DRAFT.toString()));
//        when(credentialProcedureService.getMandateeEmailFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(email));
//        when(credentialProcedureService.getMandateeCompleteNameFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(user));
//        when(credentialProcedureService.getMandatorOrganizationFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(organization));
//        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
//                .thenReturn(Mono.just(transactionCode));
//        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);
//        when(emailService.sendCredentialActivationEmail(email, CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
//                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,knowledgebaseWalletUrl,organization))
//                .thenReturn(Mono.empty());
//
//        Mono<Void> result = notificationService.sendNotification(processId, procedureId);
//
//        StepVerifier.create(result)
//                .verifyComplete();
//
//        verify(emailService, times(1)).sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString());
//    }
//
//    @Test
//    void testSendNotification_DraftStatus_EmailFailure() {
//        String transactionCode = "transactionCode";
//
//        when(credentialProcedureService.getCredentialStatusByProcedureId(procedureId))
//                .thenReturn(Mono.just(CredentialStatus.DRAFT.toString()));
//        when(credentialProcedureService.getMandateeEmailFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(email));
//        when(credentialProcedureService.getMandateeCompleteNameFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(user));
//        when(credentialProcedureService.getMandatorOrganizationFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(organization));
//        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
//                .thenReturn(Mono.just(transactionCode));
//        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);
//
//        when(emailService.sendCredentialActivationEmail(
//                email,
//                CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
//                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
//                knowledgebaseWalletUrl,
//                user,
//                organization))
//                .thenReturn(Mono.error(new RuntimeException("Email sending failed")));
//
//        Mono<Void> result = notificationService.sendNotification(processId, procedureId);
//
//        StepVerifier.create(result)
//                .expectErrorMatches(throwable -> throwable instanceof EmailCommunicationException &&
//                        throwable.getMessage().contains(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
//                .verify();
//    }
//
//
//    @Test
//    void testSendNotification_WithPendDownloadStatus() {
//        when(credentialProcedureService.getCredentialStatusByProcedureId(procedureId))
//                .thenReturn(Mono.just(CredentialStatus.PEND_DOWNLOAD.toString()));
//        when(credentialProcedureService.getMandateeEmailFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(email));
//        when(credentialProcedureService.getMandateeCompleteNameFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(user));
//        when(credentialProcedureService.getMandatorOrganizationFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(organization));
//        when(emailService.sendCredentialSignedNotification(email, CREDENTIAL_READY, user, "You can now use it with your wallet."))
//                .thenReturn(Mono.empty());
//
//        Mono<Void> result = notificationService.sendNotification(processId, procedureId);
//
//        StepVerifier.create(result)
//                .verifyComplete();
//
//        verify(emailService, times(1)).sendCredentialSignedNotification(anyString(), anyString(), anyString(), anyString());
//    }
//
//    @Test
//    void testSendNotification_WithUnhandledStatus() {
//        when(credentialProcedureService.getCredentialStatusByProcedureId(procedureId))
//                .thenReturn(Mono.just("UNHANDLED_STATUS"));
//        when(credentialProcedureService.getMandateeEmailFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(email));
//        when(credentialProcedureService.getMandateeCompleteNameFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(user));
//        when(credentialProcedureService.getMandatorOrganizationFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(organization));
//
//        Mono<Void> result = notificationService.sendNotification(processId, procedureId);
//
//        StepVerifier.create(result)
//                .verifyComplete();
//
//        verify(emailService, never()).sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
//        verify(emailService, never()).sendCredentialSignedNotification(anyString(), anyString(), anyString(), anyString());
//    }