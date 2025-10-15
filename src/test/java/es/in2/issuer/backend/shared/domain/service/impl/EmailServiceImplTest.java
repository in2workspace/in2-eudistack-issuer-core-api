package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.mail.javamail.JavaMailSender;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceImplTest {

    @Mock
    private JavaMailSender javaMailSender;

    @Mock
    private TemplateEngine templateEngine;

    @Mock
    private MailProperties mailProperties;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @InjectMocks
    private EmailServiceImpl emailService;

    @Test
    void testSendTxCodeNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("pin-email"), any(Context.class))).thenReturn("htmlContent");
        when(mailProperties.getUsername()).thenReturn("user@example.com");

        Mono<Void> result = emailService.sendTxCodeNotification("to@example.com", "subject", "1234");

        StepVerifier.create(result)
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendCredentialActivationEmail() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("activate-credential-email"), any(Context.class))).thenReturn("htmlContent");
        when(mailProperties.getUsername()).thenReturn("user@example.com");

        Mono<Void> result = emailService.sendCredentialActivationEmail("to@example.com", "subject", "link", "knowledgebaseUrl","organization");

        StepVerifier.create(result)
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendPendingCredentialNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-pending-notification"), any(Context.class))).thenReturn("htmlContent");
        when(mailProperties.getUsername()).thenReturn("user@example.com");

        Mono<Void> result = emailService.sendPendingCredentialNotification("to@example.com", "subject");

        StepVerifier.create(result)
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendCredentialSignedNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-signed-notification"), any(Context.class))).thenReturn("htmlContent");
        when(mailProperties.getUsername()).thenReturn("user@example.com");

        Mono<Void> result = emailService.sendCredentialSignedNotification("to@example.com", "subject", "additionalInfo");

        StepVerifier.create(result)
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendPendingSignatureCredentialNotification(){
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-pending-signature-notification"), any(Context.class))).thenReturn("htmlContent");
        when(mailProperties.getUsername()).thenReturn("user@example.com");

        Mono<Void> result = emailService.sendPendingSignatureCredentialNotification("to@example.com", "subject", "\"John\"", "domain");

        StepVerifier.create(result)
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriFailed_sendsEmailSuccessfully(){
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("response-uri-failed"), any(Context.class))).thenReturn("htmlContent");
        when(mailProperties.getUsername()).thenReturn("user@example.com");

        Mono<Void> result = emailService.sendResponseUriFailed("to@example.com", "productId", "guideUrl");

        StepVerifier.create(result)
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriFailed_handlesException(){
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        Mono<Void> result = emailService.sendResponseUriFailed("to@example.com", "productId", "guideUrl");

        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void sendResponseUriAcceptedWithHtml_sendsEmailSuccessfully() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(mailProperties.getUsername()).thenReturn("user@example.com");

        Mono<Void> result = emailService.sendResponseUriAcceptedWithHtml("to@example.com", "productId", "htmlContent");

        StepVerifier.create(result)
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriAcceptedWithHtml_handlesException() {
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        Mono<Void> result = emailService.sendResponseUriAcceptedWithHtml("to@example.com", "productId", "htmlContent");

        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void notifyIfCredentialStatusChanges_returnsEmptyWhenStatusDifferent() {
        // Real status is REVOKED but expected is EXPIRED -> no email should be sent
        CredentialProcedure credential = mock(CredentialProcedure.class);
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        Mono<Void> result = emailService.notifyIfCredentialStatusChanges(credential, "EXPIRED");

        StepVerifier.create(result).verifyComplete();

        // No email or credential service should be invoked
        verifyNoInteractions(javaMailSender, templateEngine, credentialProcedureService);
    }

    @Test
    void notifyIfCredentialStatusChanges_sendsExpiredEmail_andSetsTemplateVariables() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(mailProperties.getUsername()).thenReturn("sender@example.com");
        when(templateEngine.process(eq("revoked-expired-credential-email"), any(Context.class)))
                .thenReturn("htmlContent");

        // Mocked credential
        CredentialProcedure credential = mock(CredentialProcedure.class);
        UUID procedureId = UUID.randomUUID();
        when(credential.getProcedureId()).thenReturn(procedureId);
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.EXPIRED);
        when(credential.getCredentialType()).thenReturn("LEARCredentialEmployee");

        // New flow: first get credentialId, then email info
        when(credentialProcedureService.getCredentialId(credential)).thenReturn(Mono.just("cred-123"));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo(
                        "to@example.com", "ACME Corp"
                )));

        Mono<Void> result = emailService.notifyIfCredentialStatusChanges(credential, "EXPIRED");

        StepVerifier.create(result).verifyComplete();

        verify(javaMailSender).send(mimeMessage);

        // Capture the Context to check the added variables
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();

        // Subject/title for EXPIRED
        Assertions.assertEquals("Your Credential Has Expired", ctx.getVariable("title"));
        // Context variables built by buildEmailContext(...)
        Assertions.assertEquals("ACME Corp", ctx.getVariable("organization"));
        Assertions.assertEquals("cred-123", ctx.getVariable("credentialId"));
        Assertions.assertEquals("LEARCredentialEmployee", ctx.getVariable("type"));
        Assertions.assertEquals("EXPIRED", ctx.getVariable("credentialStatus"));
    }

    @Test
    void notifyIfCredentialStatusChanges_sendsRevokedEmail_andSetsRevokedTitle() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(mailProperties.getUsername()).thenReturn("sender@example.com");
        when(templateEngine.process(eq("revoked-expired-credential-email"), any(Context.class)))
                .thenReturn("htmlContent");

        CredentialProcedure credential = mock(CredentialProcedure.class);
        UUID procedureId = UUID.randomUUID();
        when(credential.getProcedureId()).thenReturn(procedureId);
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);
        when(credential.getCredentialType()).thenReturn("LEARCredentialEmployee");

        when(credentialProcedureService.getCredentialId(credential)).thenReturn(Mono.just("cred-999"));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo(
                        "to@example.com", "Umbrella Inc"
                )));

        Mono<Void> result = emailService.notifyIfCredentialStatusChanges(credential, "REVOKED");

        StepVerifier.create(result).verifyComplete();
        verify(javaMailSender).send(mimeMessage);

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();

        // Subject/title for REVOKED
        Assertions.assertEquals("Your Credential Has Been Revoked", ctx.getVariable("title"));
        // Key variables
        Assertions.assertEquals("Umbrella Inc", ctx.getVariable("organization"));
        Assertions.assertEquals("cred-999", ctx.getVariable("credentialId"));
        Assertions.assertEquals("LEARCredentialEmployee", ctx.getVariable("type"));
        Assertions.assertEquals("REVOKED", ctx.getVariable("credentialStatus"));
    }

    @Test
    void notifyIfCredentialStatusChanges_mapsErrorsToEmailCommunicationException() {
        // When getCredentialId(...) fails, it must be mapped to EmailCommunicationException
        CredentialProcedure credential = mock(CredentialProcedure.class);
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.EXPIRED);

        // ⚠️ Avoid NPE: provide a non-null procedureId
        when(credential.getProcedureId()).thenReturn(UUID.randomUUID());

        when(credentialProcedureService.getCredentialId(credential))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        Mono<Void> result = emailService.notifyIfCredentialStatusChanges(credential, "EXPIRED");

        StepVerifier.create(result)
                .expectError(es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException.class)
                .verify();

        // Ensure no email info is requested if getCredentialId(...) already failed
        verify(credentialProcedureService, never()).getCredentialOfferEmailInfoByProcedureId(anyString());
        verifyNoInteractions(javaMailSender, templateEngine);
    }

}
