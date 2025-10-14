package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.service.impl.NotificationServiceImpl;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.EmailCredentialOfferInfo;
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

import static es.in2.issuer.backend.backoffice.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
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

    // --------- HELPERS

    /** Crea un mock de CredentialProcedure amb status i (opcionalment) ownerEmail */
    private Object mockCredentialProcedureWithStatusAndOwner(Object statusEnum, String ownerEmailOrNull) throws Exception {
        // TODO substitueix Object pel tipus real CredentialProcedure
        var credentialProcedure = mock(Class.forName("es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure"));
        // getCredentialStatus() retorna l'enum (DRAFT/WITHDRAWN/PEND_DOWNLOAD)
        when(credentialProcedure.getClass().getMethod("getCredentialStatus").invoke(credentialProcedure))
                .thenReturn(null); // placeholder per evitar warning en reflexió
        // com que l'anterior línia amb reflexió és farragosa, fem stubbing amb Mockito via lenient Answer:
        // (més simple: fem un spy d'interfície/classe real si la tens accessible)

        // --- Alternativa robusta sense reflexió: usa Mockito 'when' amb cast al tipus real ---
        // CredentialProcedure cp = (CredentialProcedure) credentialProcedure;
        // when(cp.getCredentialStatus()).thenReturn((CredentialStatusEnum) statusEnum);
        // if (ownerEmailOrNull != null) when(cp.getOwnerEmail()).thenReturn(ownerEmailOrNull);

        // Perquè aquest test compili sense el tipus real, creem un "stub" via doAnswer:
        doAnswer(inv -> statusEnum).when(credentialProcedure).getClass().getMethod("getCredentialStatus").invoke(credentialProcedure);

        if (ownerEmailOrNull != null) {
            try {
                doAnswer(inv -> ownerEmailOrNull).when(credentialProcedure).getClass().getMethod("getOwnerEmail").invoke(credentialProcedure);
            } catch (NoSuchMethodException ignored) {
                // si el model no té getOwnerEmail(), elimina aquesta part i ajusta el test
            }
        }

        return credentialProcedure;
    }

    /** Construeix l'EmailCredentialOfferInfo (record amb email() i organization()) */
    private Object buildEmailOfferInfo(String email, String org) throws Exception {
        // TODO substitueix pel constructor real del teu record/DTO:
        // return new EmailCredentialOfferInfo(email, org);

        // Si el tipus exacte és desconegut aquí, fem un mock i el stubegem:
        var emailInfo = mock(Class.forName("es.in2.issuer.backend.shared.domain.model.dto.EmailCredentialOfferInfo"));
        when(emailInfo.getClass().getMethod("email").invoke(emailInfo)).thenReturn(email);
        when(emailInfo.getClass().getMethod("organization").invoke(emailInfo)).thenReturn(org);
        return emailInfo;
    }

    // --------- TESTS

    @Test
    void sendNotification_whenDraft_sendsActivationEmail() throws Exception {
        // arrange
        // CredentialProcedure amb status DRAFT
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
                eq(mandateeEmail),
                eq("Activate your new credential"),
                eq(issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode),
                eq(knowledgebaseWalletUrl),
                eq(organization)
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
                eq(mandateeEmail),
                eq("Activate your new credential"),
                eq(issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode),
                eq(knowledgebaseWalletUrl),
                eq(organization)
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
                eq(ownerEmail),
                eq("Credential Ready"),
                eq("You can now use it with your wallet.")
        )).thenReturn(Mono.empty());

        // act
        var result = notificationService.sendNotification(processId, procedureId);

        // assert
        StepVerifier.create(result).verifyComplete();

        verify(emailService, times(1))
                .sendCredentialSignedNotification(
                        eq(ownerEmail),
                        eq("Credential Ready"),
                        eq("You can now use it with your wallet.")
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
//        when(emailService.sendCredentialActivationEmail(email, "Activate your new credential",
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