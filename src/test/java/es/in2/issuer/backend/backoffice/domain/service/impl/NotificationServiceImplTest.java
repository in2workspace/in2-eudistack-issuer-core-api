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
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationServiceImplTest {

    private final String processId = "processId";
    private final String procedureId = "procedureId";

    private final String issuerUiExternalDomain = "https://example.com";
    private final String knowledgebaseWalletUrl = "https://knowledgebaseUrl.com";

    private final String mandateeEmail = "mandatee@example.com";
    private final String organization = "Acme Org";
    private final String transactionCode = "transactionCode123";
    private final String ownerEmail = "owner@example.com";

    @Mock
    private AppConfig appConfig;
    @Mock
    private EmailService emailService;
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @InjectMocks
    private NotificationServiceImpl notificationService;

    @BeforeEach
    void setup() {
        lenient().when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        lenient().when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);
    }


    // --------- TESTS

    @Test
    void sendNotification_whenDraft_sendsActivationEmail(){
        // arrange
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(DRAFT);

        CredentialOfferEmailNotificationInfo emailInfo = new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        org.mockito.Mockito.when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
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
        var result = notificationService.sendNotification(processId, procedureId);

        // assert
        StepVerifier.create(result).verifyComplete();
        verify(emailService, times(1))
                .sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString());
        verifyNoMoreInteractions(emailService);
    }

    @Test
    void sendNotification_whenWithdrawn_sendsActivationEmail() {
        // arrange
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(WITHDRAWN);

        CredentialOfferEmailNotificationInfo emailInfo = new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        org.mockito.Mockito.when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
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
        var result = notificationService.sendNotification(processId, procedureId);

        // assert
        StepVerifier.create(result).verifyComplete();
        verify(emailService, times(1))
                .sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString());
        verifyNoMoreInteractions(emailService);
    }

    @Test
    void sendNotification_whenDraft_emailFailure_mapsToEmailCommunicationException() {
        // arrange
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(DRAFT);

        CredentialOfferEmailNotificationInfo emailInfo = new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        org.mockito.Mockito.when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                .thenReturn(Mono.just(emailInfo));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId))
                .thenReturn(Mono.just(transactionCode));
        when(emailService.sendCredentialActivationEmail(
                anyString(), anyString(), anyString(), anyString(), anyString()
        )).thenReturn(Mono.error(new RuntimeException("boom")));

        // act
        var result = notificationService.sendNotification(processId, procedureId);

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
        when(credentialProcedure.getOwnerEmail()).thenReturn(ownerEmail);

        CredentialOfferEmailNotificationInfo emailInfo = new CredentialOfferEmailNotificationInfo(mandateeEmail, organization);

        when(credentialProcedureService.getCredentialProcedureById(procedureId))
                .thenReturn(Mono.just(credentialProcedure));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                .thenReturn(Mono.just(emailInfo));
        when(emailService.sendCredentialSignedNotification(
                ownerEmail,
                CREDENTIAL_READY,
                "You can now use it with your wallet.")
        ).thenReturn(Mono.empty());

        // act
        var result = notificationService.sendNotification(processId, procedureId);

        // assert
        StepVerifier.create(result).verifyComplete();

        verify(emailService, times(1))
                .sendCredentialSignedNotification(
                        ownerEmail,
                        CREDENTIAL_READY,
                        "You can now use it with your wallet."
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