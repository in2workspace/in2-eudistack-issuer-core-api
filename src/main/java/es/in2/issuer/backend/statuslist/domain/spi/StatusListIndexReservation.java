package es.in2.issuer.backend.statuslist.domain.spi;

import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import reactor.core.publisher.Mono;

public interface StatusListIndexReservation {
    Mono<StatusListIndex> reserve(Long statusListId, String procedureId);
}
