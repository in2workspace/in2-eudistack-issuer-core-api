package es.in2.issuer.backend.backoffice.domain.scheduler;

import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.EXPIRED;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.REVOKED;

@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class CredentialExpirationScheduler {

    private final CredentialProcedureRepository credentialProcedureRepository;
    private final CredentialProcedureService credentialProcedureService;
    private final EmailService emailService;

    //@Scheduled(cron = "0 0 1 * * ?") //Every day at 1:00 AM
    @Scheduled(cron = "0 */2 * * * ?") //Cada 2 minutos
    public Mono<Void> checkAndExpireCredentials() {
        log.info("Scheduled Task - Executing checkAndExpireCredentials at: {}", Instant.now());
        return credentialProcedureRepository.findAll()
                .flatMap(credential -> isExpired(credential)
                        .filter(Boolean::booleanValue)
                        .flatMap(expired -> expireCredential(credential)
                                .then(sendNotification(credential))))
                .then();
    }


    private Mono<Boolean> isExpired(CredentialProcedure credentialProcedure) {
        return Mono.justOrEmpty(credentialProcedure.getValidUntil())
                .map(validUntil -> validUntil.toInstant().isBefore(Instant.now()))
                .defaultIfEmpty(false);
    }

    private Mono<CredentialProcedure> expireCredential(CredentialProcedure credentialProcedure) {
        if (credentialProcedure.getCredentialStatus() != CredentialStatusEnum.EXPIRED) {
            credentialProcedure.setCredentialStatus(CredentialStatusEnum.EXPIRED);
            credentialProcedure.setUpdatedAt(Timestamp.from(Instant.now()));
            log.info("Expiring credential with ID: {} - New state: {}",
                    credentialProcedure.getCredentialId(),
                    credentialProcedure.getCredentialStatus());
            return credentialProcedureRepository.save(credentialProcedure);
        }
        return Mono.empty();
    }

    private Mono<Void> sendNotification(CredentialProcedure credentialProcedure) {
        log.info("Scheduled Task - Sending notification for credential with ID: {}", credentialProcedure.getCredentialId());
        return credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(credentialProcedure.getProcedureId().toString())
                .flatMap(emailCredentialOfferInfo -> {
                    log.info("Scheduled Task - Obtained email info: {}", emailCredentialOfferInfo);
                    if (credentialProcedure.getCredentialStatus().toString().equals(EXPIRED.toString())) {
                        return emailService.sendCredentialRevokedOrExpiredNotificationEmail(
                                        emailCredentialOfferInfo.email(),
                                        "Expired Credential",
                                        emailCredentialOfferInfo.user(),
                                        emailCredentialOfferInfo.organization(),
                                        credentialProcedure.getCredentialId().toString(),
                                        credentialProcedure.getCredentialType(),
                                        "Your Credential Has Expired",
                                        "expired"
                                )
                                .onErrorMap(exception ->
                                        new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
                    }else {
                        return Mono.empty();
                    }
                });
    }

}