package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationServiceImplTest {

    //todo
//    private final String processId = "processId";
//    private final String procedureId = "procedureId";
//    private final String email = "test@example.com";
//    private final String user = "Jhon";
//    private final String knowledgebaseWalletUrl = "https://knowledgebaseUrl.com";
//    private final String organization = "organization";
    private final String issuerUiExternalDomain = "https://example.com";

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
    }

    //todo
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
//        when(emailService.sendCredentialActivationEmail(email, "Activate your new credential",
//                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,knowledgebaseWalletUrl, user,organization))
//                .thenReturn(Mono.empty());
//
//        Mono<Void> result = notificationService.sendNotification(processId, procedureId);
//
//        StepVerifier.create(result)
//                .verifyComplete();
//
//        verify(emailService, times(1)).sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
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
//        when(emailService.sendCredentialSignedNotification(email, "Credential Ready", user, "You can now use it with your wallet."))
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
}