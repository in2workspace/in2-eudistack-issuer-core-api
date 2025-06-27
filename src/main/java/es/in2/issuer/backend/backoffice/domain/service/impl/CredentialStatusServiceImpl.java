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
    public Flux<String> getCredentialsStatusByListId(int listId) {
        return credentialStatusRepository.findNonceByListId(listId)
                .map(UUID::toString);
    }

    @Override
    public Mono<Void> revokeCredential(String credentialId, int listId) {
        return credentialStatusRepository.save(new StatusListIndex(UUID.fromString(credentialId), listId))
                .then();
    }
}
