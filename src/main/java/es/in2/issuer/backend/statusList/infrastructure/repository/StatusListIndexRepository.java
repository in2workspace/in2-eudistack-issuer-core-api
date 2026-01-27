package es.in2.issuer.backend.statusList.infrastructure.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface StatusListIndexRepository extends ReactiveCrudRepository<StatusListIndexRow, Long> {

    Mono<StatusListIndexRow> findByProcedureId(UUID procedureId);

    Mono<Long> countByStatusListId(Long statusListId);
}



