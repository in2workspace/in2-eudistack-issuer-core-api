package es.in2.issuer.backend.backoffice.domain.repository;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusCredentialList;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface StatusCredentialListRepository extends ReactiveCrudRepository<StatusCredentialList, UUID> {
    Mono<StatusCredentialList> findByListId(int listId);
}