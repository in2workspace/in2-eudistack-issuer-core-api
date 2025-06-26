package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListIndex;
import es.in2.issuer.backend.backoffice.domain.repository.CredentialStatusRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialStatusServiceImplTest {

    @Mock
    private CredentialStatusRepository credentialStatusRepository;

    @InjectMocks
    private CredentialStatusServiceImpl credentialStatusService;

    @Test
    void getCredentialStatus_ReturnsList() {
        StatusListIndex statusListIndex1 =
                new StatusListIndex(UUID.fromString("1b59b5f8-a66b-4694-af47-cf38db7a3d73"));
        StatusListIndex statusListIndex2 =
                new StatusListIndex(UUID.fromString("c046b54b-aa8a-4c8d-af2b-a3d60a61b80b"));

        when(credentialStatusRepository.findAll())
                .thenReturn(Flux.just(statusListIndex1, statusListIndex2));

        var result = credentialStatusService.getCredentialsStatus();

        StepVerifier
                .create(result)
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex1.getId().toString()))
                .assertNext(x -> assertThat(x).isEqualTo(statusListIndex2.getId().toString()))
                .verifyComplete();
    }
}