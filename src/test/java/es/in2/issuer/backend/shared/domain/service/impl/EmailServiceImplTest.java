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

        Mono<Void> result = emailService.sendCredentialActivationEmail("to@example.com", "subject", "link", "knowledgebaseUrl","user","organization");

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

        Mono<Void> result = emailService.sendCredentialSignedNotification("to@example.com", "subject", "\"John\"", "additionalInfo");

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
    void notifyIfCredentialStatusChanges_sendsEmailSuccessfully_andSetsTemplateVariables() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(mailProperties.getUsername()).thenReturn("sender@example.com");

        when(templateEngine.process(eq("revoked-expired-credential-email"), any(Context.class)))
                .thenReturn("htmlContent");

        CredentialProcedure credential = mock(CredentialProcedure.class);
        when(credential.getCredentialId()).thenReturn(UUID.fromString("123e4567-e89b-12d3-a456-426614174000"));
        when(credential.getCredentialType()).thenReturn("LEARCredentialEmployee");
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.EXPIRED);


        UUID procedureId = UUID.randomUUID();
        when(credential.getProcedureId()).thenReturn(procedureId);
        when(credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(procedureId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("to@example.com", "John Doe", "ACME Corp")));

        Mono<Void> result = emailService.notifyIfCredentialStatusChanges(credential, "EXPIRED");

        StepVerifier.create(result).verifyComplete();

        verify(javaMailSender).send(mimeMessage);

        ArgumentCaptor<Context> contextCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email"), contextCaptor.capture());

        Context ctx = contextCaptor.getValue();
        Assertions.assertEquals("Your Credential Has Expired", ctx.getVariable("title"));
        Assertions.assertEquals("John Doe", ctx.getVariable("user"));
        Assertions.assertEquals("ACME Corp", ctx.getVariable("organization"));
        Assertions.assertEquals("EXPIRED", ctx.getVariable("credentialStatus"));
        Assertions.assertEquals("123e4567-e89b-12d3-a456-426614174000", ctx.getVariable("credentialId"));
        Assertions.assertEquals("LEARCredentialEmployee", ctx.getVariable("type"));
    }


    @Test
    void sendCredentialRevokedOrExpiredNotificationEmail_handlesException() {
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        CredentialProcedure credential = mock(CredentialProcedure.class);
        when(credential.getProcedureId()).thenReturn(UUID.randomUUID());

        when(credential.getCredentialId()).thenReturn(UUID.fromString("123e4567-e89b-12d3-a456-426614174000"));
        when(credential.getCredentialType()).thenReturn("LEARCredentialEmployee");

        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.EXPIRED);

        when(credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(anyString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("to@example.com", "John Doe", "ACME Corp")));

        Mono<Void> result = emailService.notifyIfCredentialStatusChanges(credential, "EXPIRED");

        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

}