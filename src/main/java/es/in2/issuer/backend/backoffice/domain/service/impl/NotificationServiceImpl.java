package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.service.NotificationService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements NotificationService {

    private final AppConfig appConfig;
    private final EmailService emailService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final TranslationService translationService;

    @Override
    public Mono<Void> sendNotification(String processId, String procedureId, String organizationId) {
        log.info("sendNotification processId={} organizationId={} procedureId={}", processId, organizationId, procedureId);

        return credentialProcedureService.getCredentialProcedureById(procedureId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "CredentialProcedure not found: " + procedureId)))
                .filter(credentialProcedure -> {
                    final boolean isAdmin = appConfig.getAdminOrganizationId().equals(organizationId);
                    final boolean organizationMatches =
                            organizationId != null
                                    && credentialProcedure.getOrganizationIdentifier() != null
                                    && organizationId.equals(credentialProcedure.getOrganizationIdentifier());
                    return isAdmin || organizationMatches;
                })
                .switchIfEmpty(Mono.error(new AccessDeniedException(
                        "Organization ID does not match the credential procedure organization.")))
                .zipWhen(credentialProcedure -> credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                .flatMap(tuple -> {
                    final var credentialProcedure = tuple.getT1();
                    final var emailInfo = tuple.getT2();

                    // Prefer enum comparison over string comparison
                    return switch (credentialProcedure.getCredentialStatus()) {
                        case DRAFT, WITHDRAWN ->
                            deferredCredentialMetadataService
                                    .updateTransactionCodeInDeferredCredentialMetadata(procedureId)
                                    .flatMap(newTransactionCode ->
                                            emailService.sendCredentialActivationEmail(
                                                    emailInfo.email(),
                                                    CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                                                    appConfig.getIssuerFrontendUrl() + "/credential-offer?transaction_code=" + newTransactionCode,
                                                    appConfig.getKnowledgebaseWalletUrl(),
                                                    emailInfo.organization()
                                            )
                                    )
                                    .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));

                        case PEND_DOWNLOAD ->
                            emailService.sendCredentialSignedNotification(
                                    credentialProcedure.getEmail(),
                                    CREDENTIAL_READY,
                                    "email.you-can-use-wallet"
                            );

                        default -> Mono.empty();
                    };
                })
                .then(); // Ensure Mono<Void>
    }
}
