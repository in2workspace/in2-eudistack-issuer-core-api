package es.in2.issuer.backend.backoffice.domain.scheduler;

import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CredentialExpirationSchedulerImplTest {

    @Mock private CredentialProcedureRepository credentialProcedureRepository;
    @Mock private CredentialProcedureService credentialProcedureService;
    @Mock private EmailService emailService;

    @InjectMocks
    private CredentialExpirationScheduler credentialExpirationScheduler;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldExpireCredentialsWhenValidUntilHasPassed() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setCredentialId(UUID.randomUUID());
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

        when(credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(credentialProcedureRepository, atLeastOnce()).save(argThat(updatedCredential -> {
            boolean statusCorrect = updatedCredential.getCredentialStatus() == CredentialStatusEnum.EXPIRED;
            boolean updatedAtNotNull = updatedCredential.getUpdatedAt() != null;
            boolean updatedAtRecent = updatedCredential.getUpdatedAt().toInstant().isAfter(Instant.now().minusSeconds(10));
            return statusCorrect && updatedAtNotNull && updatedAtRecent;
        }));

        verify(emailService, never()).sendCredentialRevokedOrExpiredNotificationEmail(
                any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void shouldSendEmailWhenCredentialExpires() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setCredentialId(UUID.randomUUID());
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

        when(credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(credential.getProcedureId().toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo(
                        "to@mail", "userX", "orgY")));

        when(emailService.sendCredentialRevokedOrExpiredNotificationEmail(
                anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString()
        )).thenReturn(Mono.empty());

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .verifyComplete();

        verify(emailService, times(1)).sendCredentialRevokedOrExpiredNotificationEmail(
                eq("to@mail"),
                eq("Expired Credential"),
                eq("userX"),
                eq("orgY"),
                eq(credential.getCredentialId().toString()),
                eq("LEARCredentialEmployee"),
                eq("Your Credential Has Expired"),
                eq("expired")
        );
    }

    @Test
    void shouldMapEmailErrorToEmailCommunicationException() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setCredentialId(UUID.randomUUID());
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

        when(credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(credential.getProcedureId().toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo(
                        "to@mail", "userX", "orgY")));

        when(emailService.sendCredentialRevokedOrExpiredNotificationEmail(
                anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString()
        )).thenReturn(Mono.error(new RuntimeException("smtp down")));

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectError(EmailCommunicationException.class)
                .verify();

        verify(emailService, times(1)).sendCredentialRevokedOrExpiredNotificationEmail(
                anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldNotExpireCredentialsIfValidUntilHasNotPassed() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setCredentialId(UUID.randomUUID());
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().plusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(credentialProcedureRepository, never()).save(any(CredentialProcedure.class));
        verify(emailService, never()).sendCredentialRevokedOrExpiredNotificationEmail(
                any(), any(), any(), any(), any(), any(), any(), any());

        assertEquals(CredentialStatusEnum.VALID, credential.getCredentialStatus());
        assertNull(credential.getUpdatedAt());
    }
}
