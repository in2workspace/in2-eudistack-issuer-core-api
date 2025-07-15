package es.in2.issuer.backend.backoffice.domain.repository;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListIndex;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

import java.util.UUID;

public interface CredentialStatusRepository extends ReactiveCrudRepository<StatusListIndex, UUID> {
    Flux<StatusListIndex> findByListId(int listId);
}
