package es.in2.issuer.backend.statuslist.infrastructure.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface StatusListIndexRepository extends ReactiveCrudRepository<StatusListIndex, Long> {

    Mono<StatusListIndex> findByProcedureId(UUID procedureId);

    Mono<Long> countByStatusListId(Long statusListId);
}



