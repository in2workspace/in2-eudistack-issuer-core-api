package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListIndex;
import es.in2.issuer.backend.backoffice.domain.repository.CredentialStatusRepository;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialStatusServiceImpl implements CredentialStatusService {

    private final CredentialStatusRepository credentialStatusRepository;

    @Override
    public Flux<String> getCredentialsByListId(int listId) {
        return credentialStatusRepository.findByListId(listId)
                .map(StatusListIndex::getNonce);
    }

    @Override
    public Mono<Void> revokeCredential(int listId, CredentialStatus credentialStatus) {
        StatusListIndex statusListIndex = new StatusListIndex();
        String nonce = credentialStatus.statusListIndex();
        statusListIndex.setNonce(nonce);
        statusListIndex.setListId(listId);
        return credentialStatusRepository.save(statusListIndex)
                .then();
    }
}
