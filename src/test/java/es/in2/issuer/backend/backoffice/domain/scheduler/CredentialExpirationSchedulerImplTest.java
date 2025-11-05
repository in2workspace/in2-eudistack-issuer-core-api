package es.in2.issuer.backend.backoffice.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
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

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.EXPIRED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

class CredentialExpirationSchedulerImplTest {

    @Mock private CredentialProcedureRepository credentialProcedureRepository;
    @Mock private EmailService emailService;

    @InjectMocks
    private CredentialExpirationScheduler credentialExpirationScheduler;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldExpireCredentialsWhenValidUntilHasPassed() {
        // Arrange
        CredentialProcedure credential = new CredentialProcedure();
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));

        // Simulate auditing @LastModifiedDate by setting updatedAt on save
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> {
                    CredentialProcedure cp = invocation.getArgument(0);
                    cp.setUpdatedAt(Instant.now());
                    return Mono.just(cp);
                });

        when(emailService.notifyIfCredentialStatusChanges(any(CredentialProcedure.class), anyString()))
                .thenReturn(Mono.empty());

        // Capture a baseline "now" so the assertion isn't racy
        Instant baseline = Instant.now();

        // Act
        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        // Assert
        verify(credentialProcedureRepository, atLeastOnce()).save(argThat(updated -> {
            // Safe null-check to avoid NPE
            Instant ua = updated.getUpdatedAt();
            return updated.getCredentialStatus() == EXPIRED
                    && ua != null
                    && ua.isAfter(baseline.minusSeconds(1));
        }));
    }

    @Test
    void shouldSendEmailWhenCredentialExpires() {
        // Arrange
        CredentialProcedure credential = new CredentialProcedure();
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> {
                    CredentialProcedure cp = invocation.getArgument(0);
                    // Simulate auditing
                    cp.setUpdatedAt(Instant.now());
                    return Mono.just(cp);
                });

        when(emailService.notifyIfCredentialStatusChanges(any(CredentialProcedure.class), anyString()))
                .thenReturn(Mono.empty());

        // Act
        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .verifyComplete();

        // Assert: email notification is sent with EXPIRED status
        verify(emailService, times(1)).notifyIfCredentialStatusChanges(credential, "EXPIRED");
    }

    @Test
    void shouldNotExpireCredentialsIfValidUntilHasNotPassed() {
        // Arrange
        CredentialProcedure credential = new CredentialProcedure();
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().plusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));

        // Even if save were stubbed, we expect it to never be called
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> {
                    CredentialProcedure cp = invocation.getArgument(0);
                    cp.setUpdatedAt(Instant.now());
                    return Mono.just(cp);
                });

        // Act
        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        // Assert
        verify(credentialProcedureRepository, never()).save(any(CredentialProcedure.class));
        verify(emailService, never()).notifyIfCredentialStatusChanges(any(), any());

        assertEquals(CredentialStatusEnum.VALID, credential.getCredentialStatus());
        assertNull(credential.getUpdatedAt(), "updatedAt should remain null because save() was never called");
    }
}
