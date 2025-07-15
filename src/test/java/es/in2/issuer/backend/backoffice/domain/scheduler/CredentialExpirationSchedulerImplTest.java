package es.in2.issuer.backend.backoffice.domain.scheduler;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

class CredentialExpirationSchedulerImplTest {

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private CredentialExpirationScheduler credentialExpirationScheduler;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldExpireCredentialsWhenValidUntilHasPassed() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setCredentialId(java.util.UUID.randomUUID());
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(credentialProcedureRepository, atLeastOnce()).save(argThat(updatedCredential -> {
            boolean statusCorrect = updatedCredential.getCredentialStatus() == CredentialStatusEnum.EXPIRED;
            boolean updatedAtNotNull = updatedCredential.getUpdatedAt() != null;
            boolean updatedAtRecent = updatedCredential.getUpdatedAt().toInstant().isAfter(Instant.now().minusSeconds(10));

            return statusCorrect && updatedAtNotNull && updatedAtRecent;
        }));
    }

    @Test
    void shouldNotExpireCredentialsIfValidUntilHasNotPassed() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setCredentialId(java.util.UUID.randomUUID());
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().plusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(credentialProcedureRepository, never()).save(any(CredentialProcedure.class));

        assertEquals(CredentialStatusEnum.VALID, credential.getCredentialStatus());
        assertNull(credential.getUpdatedAt());
    }
}
