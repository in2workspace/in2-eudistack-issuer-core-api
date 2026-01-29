package es.in2.issuer.backend.credentialstatus.infrastructure.adapter;


import es.in2.issuer.backend.credentialstatus.domain.model.entities.LegacyStatusListIndex;
import es.in2.issuer.backend.credentialstatus.domain.service.LegacyCredentialStatusQuery;
import es.in2.issuer.backend.credentialstatus.infrastructure.repository.LegacyCredentialStatusRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

@Slf4j
@Service
@RequiredArgsConstructor
public class LegacyCredentialStatusQueryImpl implements LegacyCredentialStatusQuery {

    private final LegacyCredentialStatusRepository  legacyCredentialStatusRepository;

    @Override
    public Flux<String> getNoncesByListId(String processId, int listId) {
        log.info("Process ID: {} - LegacyCredentialStatusQueryImpl - getNoncesByListId: {}", processId, listId);
        return legacyCredentialStatusRepository.findByListId(listId)
                .map(LegacyStatusListIndex::getNonce);
    }
}
