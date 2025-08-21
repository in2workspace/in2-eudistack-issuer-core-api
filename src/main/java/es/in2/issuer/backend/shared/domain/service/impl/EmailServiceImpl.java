package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.InputStreamSource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.StreamUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.InputStream;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.UTF_8;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {
    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;
    private final MailProperties mailProperties;
    private final CredentialProcedureService credentialProcedureService;

    @Override
    public Mono<Void> sendTxCodeNotification(String to, String subject, String pin) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(subject);

            Context context = new Context();
            context.setVariable("pin", pin);
            String htmlContent = templateEngine.process("pin-email", context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        })
                .subscribeOn(Schedulers.boundedElastic()).then()
                .onErrorMap(ex -> new EmailCommunicationException("Error when sending tx code notification"));
    }

    @Override
    public Mono<Void> sendCredentialActivationEmail(String to, String subject, String link, String knowledgebaseWalletUrl, String user, String organization) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(subject);

            ClassPathResource imgResource = new ClassPathResource("static/images/qr-wallet.png");
            String imageResourceName = imgResource.getFilename();

            InputStream imageStream = imgResource.getInputStream();
            byte[] imageBytes = StreamUtils.copyToByteArray(imageStream);

            Context context = new Context();
            context.setVariable("link", link);
            context.setVariable("user", user);
            context.setVariable("organization", organization);
            context.setVariable("knowledgebaseWalletUrl", knowledgebaseWalletUrl);
            context.setVariable("imageResourceName", "cid:" + imageResourceName);

            String htmlContent = templateEngine.process("activate-credential-email", context);
            helper.setText(htmlContent, true);

            final InputStreamSource imageSource = new ByteArrayResource(imageBytes);
            if (imageResourceName != null) {
                helper.addInline(imageResourceName, imageSource, MimeTypeUtils.IMAGE_PNG_VALUE);
            }

            javaMailSender.send(mimeMessage);

            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> sendPendingCredentialNotification(String to, String subject) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(subject);

            Context context = new Context();
            String htmlContent = templateEngine.process("credential-pending-notification", context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
    @Override
    public Mono<Void> sendPendingSignatureCredentialNotification(String to, String subject, String id, String domain){
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(subject);

            Context context = new Context();
            context.setVariable("id", id);
            context.setVariable("domain", domain);
            String htmlContent = templateEngine.process("credential-pending-signature-notification", context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
    @Override
    public Mono<Void> sendCredentialSignedNotification(String to, String subject, String firstName, String additionalInfo) {
        firstName = firstName.replace("\"", "");
        final String finalName = firstName;
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(subject);

            Context context = new Context();
            context.setVariable("name", finalName);
            context.setVariable("additionalInfo", additionalInfo);
            String htmlContent = templateEngine.process("credential-signed-notification", context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> sendResponseUriFailed(String to, String productId, String guideUrl) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject("Certification Submission to Marketplace Unsuccessful");

            Context context = new Context();
            context.setVariable("productId", productId);
            context.setVariable("guideUrl", guideUrl);
            String htmlContent = templateEngine.process("response-uri-failed", context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> sendResponseUriAcceptedWithHtml(String to, String productId, String htmlContent) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject("Missing Documents for Certification: " + productId);

            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> notifyIfCredentialStatusChanges(CredentialProcedure credential, String expectedStatus) {
        if (!credential.getCredentialStatus().toString().equalsIgnoreCase(expectedStatus)) {
            return Mono.empty();
        }
        return credentialProcedureService
                .getEmailCredentialOfferInfoByProcedureId(credential.getProcedureId().toString())
                .flatMap(info ->
                        sendCredentialRevokedOrExpiredNotificationEmail(
                                info.email(),
                                info.user(),
                                info.organization(),
                                credential.getCredentialId().toString(),
                                credential.getCredentialType(),
                                expectedStatus
                        )
                )
                .onErrorMap(e -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .doOnError(e -> log.error("Error sending '{}' email for credential {}", expectedStatus, credential.getCredentialId()));
    }

    private Mono<Void> sendCredentialRevokedOrExpiredNotificationEmail(String to,String user,String organization,String credentialId,String type,String credentialStatus){
        return Mono.fromCallable(() -> {
            try {
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);

                helper.setFrom(mailProperties.getUsername());
                helper.setTo(to);

                Context context = buildEmailContext(user, organization, credentialId, type, credentialStatus);

                switch (credentialStatus) {
                    case "REVOKED" -> {
                        helper.setSubject("Revoked Credential");
                        context.setVariable("title", "Your Credential Has Been Revoked");
                    }
                    case "EXPIRED" -> {
                        helper.setSubject("Expired Credential");
                        context.setVariable("title", "Your Credential Has Expired");
                    }
                    default -> helper.setSubject("Credential Notification");

                }
                String htmlContent = templateEngine.process("revoked-expired-credential-email", context);
                helper.setText(htmlContent, true);

                javaMailSender.send(mimeMessage);
            } catch (MessagingException e) {
                throw new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE);
            }

            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    private Context buildEmailContext(String user, String organization, String credentialId, String type, String credentialStatus) {
        Context context = new Context();
        context.setVariable("user", user);
        context.setVariable("organization", organization);
        context.setVariable("credentialId", credentialId);
        context.setVariable("type", type);
        context.setVariable("credentialStatus", credentialStatus);
        return context;
    }

}
