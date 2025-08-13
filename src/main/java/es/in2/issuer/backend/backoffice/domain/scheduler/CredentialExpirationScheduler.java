package es.in2.issuer.backend.backoffice.domain.scheduler;


import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
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
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.EXPIRED;

@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class CredentialExpirationScheduler {

    private final CredentialProcedureRepository credentialProcedureRepository;
    private final EmailService emailService;

    @Scheduled(cron = "0 0 1 * * ?") //Every day at 1:00 AM
    public Mono<Void> checkAndExpireCredentials() {
        log.info("Scheduled Task - Executing checkAndExpireCredentials at: {}", Instant.now());
        return credentialProcedureRepository.findAll()
                .flatMap(credential -> isExpiredAndNotAlreadyMarked(credential)
                        .filter(Boolean::booleanValue)
                        .flatMap(expired -> expireCredential(credential)
                                .then(emailService.notifyIfCredentialStatusChanges(credential, EXPIRED.toString()))))
                .then();
    }


    private Mono<Boolean> isExpiredAndNotAlreadyMarked(CredentialProcedure credentialProcedure) {
        return Mono.justOrEmpty(credentialProcedure.getValidUntil())
                .map(validUntil ->
                        validUntil.toInstant().isBefore(Instant.now())
                                && credentialProcedure.getCredentialStatus() != CredentialStatusEnum.EXPIRED
                )
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

}