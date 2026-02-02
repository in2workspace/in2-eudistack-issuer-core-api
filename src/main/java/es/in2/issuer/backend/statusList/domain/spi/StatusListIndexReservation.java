package es.in2.issuer.backend.statusList.domain.spi;

import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndex;
import reactor.core.publisher.Mono;

public interface StatusListIndexReservation {
    Mono<StatusListIndex> reserve(Long statusListId, String procedureId);
}
