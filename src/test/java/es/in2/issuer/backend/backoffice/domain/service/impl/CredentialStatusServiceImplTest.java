package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListIndex;
import es.in2.issuer.backend.backoffice.domain.repository.CredentialStatusRepository;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialStatusServiceImplTest {

    @Mock
    private CredentialStatusRepository credentialStatusRepository;

    @InjectMocks
    private CredentialStatusServiceImpl credentialStatusService;

    @Test
    void getCredentialStatus_ReturnsList() {
        int listId = 1;
        StatusListIndex statusListIndex1 = new StatusListIndex();
        statusListIndex1.setNonce("1b59b5f8-a66b-4694-af47-cf38db7a3d73");
        statusListIndex1.setListId(listId);

        StatusListIndex statusListIndex2 = new StatusListIndex();
        statusListIndex2.setNonce("c046b54b-aa8a-4c8d-af2b-a3d60a61b80b");
        statusListIndex2.setListId(listId);

        when(credentialStatusRepository.findByListId(listId))
                .thenReturn(Flux.just(statusListIndex1, statusListIndex2));

        var result = credentialStatusService.getCredentialsByListId(listId);

        StepVerifier
                .create(result)
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex1.getNonce()))
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex2.getNonce()))
                .verifyComplete();
    }

    @Test
    void revokeCredential_ReturnsVoid() {
        StatusListIndex statusListIndex1 = new StatusListIndex();
        String nonce = "1b59b5f8-a66b-4694-af47-cf38db7a3d73";
        statusListIndex1.setNonce(nonce);
        statusListIndex1.setListId(1);

        when(credentialStatusRepository.save(any(StatusListIndex.class)))
                .thenReturn(Mono.just(statusListIndex1));

        int listId = 1;
        CredentialStatus credentialStatus = CredentialStatus.builder()
                .statusListIndex(nonce).build();
        var result = credentialStatusService.revokeCredential(listId, credentialStatus);

        StepVerifier
                .create(result)
                .verifyComplete();

        ArgumentCaptor<StatusListIndex> captor = ArgumentCaptor.forClass(StatusListIndex.class);
        verify(credentialStatusRepository).save(captor.capture());

        assertThat(statusListIndex1.getNonce())
                .isEqualTo(captor.getValue().getNonce());
    }
}