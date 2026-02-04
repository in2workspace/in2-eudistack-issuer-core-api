package es.in2.issuer.backend.statuslist.domain.service.impl;


import es.in2.issuer.backend.statuslist.domain.model.entities.LegacyStatusListIndex;
import es.in2.issuer.backend.statuslist.domain.service.LegacyCredentialStatusQuery;
import es.in2.issuer.backend.statuslist.infrastructure.repository.LegacyCredentialStatusRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

// Legacy service used to handle credentials with a PlainListEntry credentialStatus.
// TODO Remove once the last credential of this type expires in DOME.
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
