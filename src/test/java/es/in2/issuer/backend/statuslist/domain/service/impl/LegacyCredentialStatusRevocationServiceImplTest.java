package es.in2.issuer.backend.statuslist.domain.service.impl;

import es.in2.issuer.backend.statuslist.domain.model.entities.LegacyStatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.LegacyCredentialStatusRepository;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LegacyCredentialStatusRevocationServiceImplTest {

    @Mock
    private LegacyCredentialStatusRepository legacyCredentialStatusRepository;

    private LegacyCredentialStatusRevocationServiceImpl sut;

    @BeforeEach
    void setUp() {
        sut = new LegacyCredentialStatusRevocationServiceImpl(legacyCredentialStatusRepository);
    }

    @Test
    void revoke_shouldSaveEntityAndComplete_whenNonceIsValid() {
        int listId = 10;

        CredentialStatus credentialStatus = mock(CredentialStatus.class);
        when(credentialStatus.statusListIndex()).thenReturn("nonce-123");

        when(legacyCredentialStatusRepository.save(any(LegacyStatusListIndex.class)))
                .thenReturn(Mono.just(new LegacyStatusListIndex()));

        StepVerifier.create(sut.revoke(listId, credentialStatus))
                .verifyComplete();

        ArgumentCaptor<LegacyStatusListIndex> captor = ArgumentCaptor.forClass(LegacyStatusListIndex.class);
        verify(legacyCredentialStatusRepository, times(1)).save(captor.capture());
        verifyNoMoreInteractions(legacyCredentialStatusRepository);

        LegacyStatusListIndex saved = captor.getValue();
        assertEquals(listId, saved.getListId());
        assertEquals("nonce-123", saved.getNonce());
    }

    @Test
    void revoke_shouldError_whenNonceIsNull() {
        int listId = 10;

        CredentialStatus credentialStatus = mock(CredentialStatus.class);
        when(credentialStatus.statusListIndex()).thenReturn(null);

        StepVerifier.create(sut.revoke(listId, credentialStatus))
                .expectErrorSatisfies(ex -> assertEquals(
                        "credentialStatus.statusListIndex (nonce) cannot be null/blank",
                        ex.getMessage()
                ))
                .verify();

        verifyNoInteractions(legacyCredentialStatusRepository);
    }

    @Test
    void revoke_shouldError_whenNonceIsBlank() {
        int listId = 10;

        CredentialStatus credentialStatus = mock(CredentialStatus.class);
        when(credentialStatus.statusListIndex()).thenReturn("   ");

        StepVerifier.create(sut.revoke(listId, credentialStatus))
                .expectErrorSatisfies(ex -> assertEquals(
                        "credentialStatus.statusListIndex (nonce) cannot be null/blank",
                        ex.getMessage()
                ))
                .verify();

        verifyNoInteractions(legacyCredentialStatusRepository);
    }

    @Test
    void revoke_shouldThrowNullPointerException_whenCredentialStatusIsNull() {
        int listId = 10;

        NullPointerException ex = assertThrows(NullPointerException.class, () -> sut.revoke(listId, null));
        assertEquals("credentialStatus cannot be null", ex.getMessage());

        verifyNoInteractions(legacyCredentialStatusRepository);
    }

    @Test
    void revoke_shouldPropagateRepositoryError() {
        int listId = 10;

        CredentialStatus credentialStatus = mock(CredentialStatus.class);
        when(credentialStatus.statusListIndex()).thenReturn("nonce-123");

        RuntimeException repoError = new RuntimeException("db down");
        when(legacyCredentialStatusRepository.save(any(LegacyStatusListIndex.class)))
                .thenReturn(Mono.error(repoError));

        StepVerifier.create(sut.revoke(listId, credentialStatus))
                .expectErrorMatches(ex -> ex == repoError)
                .verify();

        verify(legacyCredentialStatusRepository, times(1)).save(any(LegacyStatusListIndex.class));
        verifyNoMoreInteractions(legacyCredentialStatusRepository);
    }
}

