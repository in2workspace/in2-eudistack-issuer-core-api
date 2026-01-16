package es.in2.issuer.backend.credentialStatus.infrastructure.adapter;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListIndex;
import es.in2.issuer.backend.credentialStatus.domain.service.LegacyCredentialStatusQuery;
import es.in2.issuer.backend.credentialStatus.infrastructure.repository.LegacyCredentialStatusRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

@Service
@RequiredArgsConstructor
public class LegacyCredentialStatusQueryImpl implements LegacyCredentialStatusQuery {

    private final LegacyCredentialStatusRepository  legacyCredentialStatusRepository;

    @Override
    public Flux<String> getNoncesByListId(int listId) {
        return legacyCredentialStatusRepository.findByListId(listId)
                .map(StatusListIndex::getNonce);
    }
}
