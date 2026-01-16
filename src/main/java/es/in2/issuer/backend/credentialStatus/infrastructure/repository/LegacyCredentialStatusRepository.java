package es.in2.issuer.backend.credentialStatus.infrastructure.repository;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListIndex;
import es.in2.issuer.backend.credentialStatus.domain.model.entities.LegacyStatusListIndex;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

import java.util.UUID;

//el nom s'haurà de tornar a posar sense legacy per coincidir amb nom taula
public interface LegacyCredentialStatusRepository extends ReactiveCrudRepository<LegacyStatusListIndex, UUID> {
    Flux<StatusListIndex> findByListId(int listId);
}


