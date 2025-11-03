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
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.*;

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
        return credentialProcedureService.getCredentialProcedureById(procedureId)
                .flatMap(credentialProcedure -> {
                    // Admin can bypass organization check
                    final boolean isAdmin = IN2_ORGANIZATION_IDENTIFIER.equals(organizationId);

                    // Ensure provided organizationId matches the one stored on the procedure
                    final boolean organizationMatches =
                            organizationId != null
                                    && credentialProcedure.getOrganizationIdentifier() != null
                                    && organizationId.equals(credentialProcedure.getOrganizationIdentifier());

                    if (!isAdmin && !organizationMatches) {
                        return Mono.error(new org.springframework.security.access.AccessDeniedException(
                                "Organization ID does not match the credential procedure organization."));
                    }

                    return credentialProcedureService
                            .buildCredentialOfferEmailInfoFromProcedure(credentialProcedure) // ← no extra DB call
                            .flatMap(emailCredentialOfferInfo -> {
                                // TODO remove WITHDRAWN in future versions; kept for backward compatibility
                                final String status = credentialProcedure.getCredentialStatus().toString();

                                if (status.equals(DRAFT.toString()) || status.equals(WITHDRAWN.toString())) {
                                    return deferredCredentialMetadataService
                                            .updateTransactionCodeInDeferredCredentialMetadata(procedureId)
                                            .flatMap(newTransactionCode -> emailService.sendCredentialActivationEmail(
                                                    emailCredentialOfferInfo.email(),
                                                    CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                                                    appConfig.getIssuerFrontendUrl()
                                                            + "/credential-offer?transaction_code=" + newTransactionCode,
                                                    appConfig.getKnowledgebaseWalletUrl(),
                                                    emailCredentialOfferInfo.organization()
                                            ))
                                            .onErrorMap(ex -> new EmailCommunicationException(
                                                    MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
                                } else if (status.equals(PEND_DOWNLOAD.toString())) {
                                    return emailService.sendCredentialSignedNotification(
                                            credentialProcedure.getEmail(),
                                            CREDENTIAL_READY,
                                            "email.you-can-use-wallet"
                                    );
                                }
                                return Mono.empty();
                            });
                });
    }


}