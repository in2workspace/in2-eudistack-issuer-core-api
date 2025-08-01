package es.in2.issuer.backend.backoffice.domain.service.impl;


import es.in2.issuer.backend.backoffice.domain.service.NotificationService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements NotificationService {

    private final AppConfig appConfig;
    private final EmailService emailService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;

    @Override
    public Mono<Void> sendNotification(String processId, String procedureId) {
        return credentialProcedureService.getCredentialProcedureById(procedureId)
                        .flatMap(credentialProcedure -> credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(procedureId)
                                .flatMap(emailCredentialOfferInfo -> {
                                            // TODO we need to remove the withdraw status from the condition since the v1.2.0 version is deprecated but in order to support retro compatibility issues we will keep it for now.
                                            if (credentialProcedure.getCredentialStatus().toString().equals(DRAFT.toString()) || credentialProcedure.getCredentialStatus().toString().equals(WITHDRAWN.toString())) {
                                                return deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId)
                                                        .flatMap(newTransactionCode -> emailService.sendCredentialActivationEmail(
                                                                emailCredentialOfferInfo.email(),
                                                                "Activate your new credential",
                                                                appConfig.getIssuerFrontendUrl() + "/credential-offer?transaction_code=" + newTransactionCode,
                                                                appConfig.getKnowledgebaseWalletUrl(),
                                                                emailCredentialOfferInfo.user(),
                                                                emailCredentialOfferInfo.organization()
                                                        ))
                                                        .onErrorMap(exception ->
                                                                new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
                                            } else if (credentialProcedure.getCredentialStatus().toString().equals(PEND_DOWNLOAD.toString())) {
                                                return emailService.sendCredentialSignedNotification(credentialProcedure.getOwnerEmail(), "Credential Ready", emailCredentialOfferInfo.user(), "You can now use it with your wallet.");
                                            } else {
                                                return Mono.empty();
                                            }
                                        }
                                )
                        );
    }

}