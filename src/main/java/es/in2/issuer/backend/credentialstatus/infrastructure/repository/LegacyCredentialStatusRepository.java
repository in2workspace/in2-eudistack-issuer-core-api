package es.in2.issuer.backend.credentialstatus.infrastructure.repository;

import es.in2.issuer.backend.credentialstatus.domain.model.entities.LegacyStatusListIndex;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

import java.util.UUID;


public interface LegacyCredentialStatusRepository extends ReactiveCrudRepository<LegacyStatusListIndex, UUID> {
    Flux<LegacyStatusListIndex> findByListId(int listId);
}


