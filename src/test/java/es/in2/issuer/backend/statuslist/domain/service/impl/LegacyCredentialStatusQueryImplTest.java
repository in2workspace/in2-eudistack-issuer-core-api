package es.in2.issuer.backend.statuslist.domain.service.impl;

import es.in2.issuer.backend.statuslist.domain.model.entities.LegacyStatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.LegacyCredentialStatusRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LegacyCredentialStatusQueryImplTest {

    @Mock
    private LegacyCredentialStatusRepository legacyCredentialStatusRepository;

    private LegacyCredentialStatusQueryImpl sut;

    @BeforeEach
    void setUp() {
        sut = new LegacyCredentialStatusQueryImpl(legacyCredentialStatusRepository);
    }

    @Test
    void getNoncesByListId_shouldReturnMappedNonces() {
        String processId = "p-123";
        int listId = 42;

        LegacyStatusListIndex index1 = mock(LegacyStatusListIndex.class);
        LegacyStatusListIndex index2 = mock(LegacyStatusListIndex.class);

        when(index1.getNonce()).thenReturn("nonce-1");
        when(index2.getNonce()).thenReturn("nonce-2");

        when(legacyCredentialStatusRepository.findByListId(listId))
                .thenReturn(Flux.just(index1, index2));

        StepVerifier.create(sut.getNoncesByListId(processId, listId))
                .expectNext("nonce-1", "nonce-2")
                .verifyComplete();

        verify(legacyCredentialStatusRepository, times(1)).findByListId(listId);
        verifyNoMoreInteractions(legacyCredentialStatusRepository);
    }

    @Test
    void getNoncesByListId_shouldReturnEmptyWhenRepositoryReturnsEmpty() {
        String processId = "p-123";
        int listId = 42;

        when(legacyCredentialStatusRepository.findByListId(listId))
                .thenReturn(Flux.empty());

        StepVerifier.create(sut.getNoncesByListId(processId, listId))
                .verifyComplete();

        verify(legacyCredentialStatusRepository, times(1)).findByListId(listId);
        verifyNoMoreInteractions(legacyCredentialStatusRepository);
    }

    @Test
    void getNoncesByListId_shouldPropagateErrorFromRepository() {
        String processId = "p-123";
        int listId = 42;

        RuntimeException repoError = new RuntimeException("db down");

        when(legacyCredentialStatusRepository.findByListId(listId))
                .thenReturn(Flux.error(repoError));

        StepVerifier.create(sut.getNoncesByListId(processId, listId))
                .expectErrorMatches(ex -> ex == repoError)
                .verify();

        verify(legacyCredentialStatusRepository, times(1)).findByListId(listId);
        verifyNoMoreInteractions(legacyCredentialStatusRepository);
    }
}

