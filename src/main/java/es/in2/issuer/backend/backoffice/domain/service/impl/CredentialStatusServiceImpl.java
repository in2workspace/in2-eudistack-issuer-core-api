package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListIndex;
import es.in2.issuer.backend.backoffice.domain.repository.CredentialStatusRepository;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialStatusServiceImpl implements CredentialStatusService {

    private final CredentialStatusRepository credentialStatusRepository;

    @Override
    public Flux<String> getCredentialsByListId(int listId) {
        return credentialStatusRepository.findByListId(listId)
                .map(statusListIndex -> statusListIndex.getNonce().toString());
    }

    @Override
    public Mono<Void> revokeCredential(String credentialId, int listId) {
        StatusListIndex statusListIndex = new StatusListIndex();
        statusListIndex.setNonce(UUID.fromString(credentialId));
        statusListIndex.setListId(listId);
        return credentialStatusRepository.save(statusListIndex)
                .then();
    }
}
