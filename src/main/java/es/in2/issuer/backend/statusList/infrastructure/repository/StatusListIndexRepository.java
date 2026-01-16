package es.in2.issuer.backend.statusList.infrastructure.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface StatusListIndexRepository extends ReactiveCrudRepository<StatusListIndexRow, Long> {

    Mono<StatusListIndexRow> findByprocedureId(String procedureId);

    Mono<Long> countByStatusListId(Long statusListId);

    Mono<Boolean> existsByStatusListIdAndIdx(Long statusListId, Integer idx);
}



