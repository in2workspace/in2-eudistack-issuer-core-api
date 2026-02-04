package es.in2.issuer.backend.statuslist.infrastructure.repository;

import es.in2.issuer.backend.statuslist.domain.model.entities.LegacyStatusListIndex;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

import java.util.UUID;

// Legacy repository used to handle status list indexes with a PlainListEntry credentialStatus.
// TODO Remove once the last credential of this type expires in DOME.
public interface LegacyCredentialStatusRepository extends ReactiveCrudRepository<LegacyStatusListIndex, UUID> {
    Flux<LegacyStatusListIndex> findByListId(int listId);
}


