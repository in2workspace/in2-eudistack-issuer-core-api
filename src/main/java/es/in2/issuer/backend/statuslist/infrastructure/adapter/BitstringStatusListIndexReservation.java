package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import es.in2.issuer.backend.statuslist.domain.exception.IndexReservationExhaustedException;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListIndexAllocator;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListIndexReservation;
import es.in2.issuer.backend.statuslist.domain.spi.UniqueViolationClassifier;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.CAPACITY_BITS;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@Slf4j
@Service
@RequiredArgsConstructor
public class BitstringStatusListIndexReservation implements StatusListIndexReservation {

    private final StatusListIndexRepository statusListIndexRepository;
    private final StatusListIndexAllocator indexAllocator;
    private final UniqueViolationClassifier uniqueViolationClassifier;

    @Override
    public Mono<StatusListIndex> reserve(Long statusListId, String procedureId) {
        return reserveWithRetry(statusListId, procedureId);
    }

    private Mono<StatusListIndex> reserveWithRetry(Long statusListId, String procedureId) {
        log.info("reserveOnSpecificList - statusListId: {} - procedureId: {}", statusListId, procedureId);
        requireNonNullParam(statusListId, "statusListId");
        requireNonNullParam(procedureId, "procedureId");

        long maxAttempts = 30;

        return Mono.defer(() -> tryReserveOnce(statusListId, procedureId))
                .retryWhen(
                        Retry.backoff(maxAttempts - 1L, Duration.ofMillis(5))
                                .maxBackoff(Duration.ofMillis(100))
                                .filter(t -> {
                                    UniqueViolationClassifier.Kind k = uniqueViolationClassifier.classify(t);
                                    return k == UniqueViolationClassifier.Kind.IDX || k == UniqueViolationClassifier.Kind.UNKNOWN;
                                })
                                .doBeforeRetry(rs -> {
                                    long attempt = rs.totalRetries() + 2;
                                    log.debug(
                                            "action=reserveStatusListIndex retryReason=uniqueCollision statusListId={} procedureId={} attempt={}/{}",
                                        statusListId, procedureId, attempt, maxAttempts
                                );
                                })
                )
                .onErrorMap(this::maybeWrapAsExhausted);
    }

    private Mono<StatusListIndex> tryReserveOnce(Long statusListId, String procedureId) {
        int idx = indexAllocator.proposeIndex(CAPACITY_BITS);

        StatusListIndex row = new StatusListIndex(
                null,
                statusListId,
                idx,
                UUID.fromString(procedureId),
                Instant.now()
        );

        return statusListIndexRepository.save(row)
                .doOnNext(saved -> log.debug(
                        "Saved StatusListIndex: id={}, statusListId={}, idx={}, procedureId={}, createdAt={}",
                        saved.id(),
                        saved.statusListId(),
                        saved.idx(),
                        saved.procedureId(),
                        saved.createdAt()
                ))
                .onErrorResume(t -> {
                    UniqueViolationClassifier.Kind k = uniqueViolationClassifier.classify(t);
                    log.debug(
                            "action=tryReserveOnce constraintKind={} statusListId={} idx={} procedureId={}",
                            k, statusListId, idx, procedureId
                    );

                    if (k == UniqueViolationClassifier.Kind.PROCEDURE_ID) {
                        return statusListIndexRepository.findByProcedureId(UUID.fromString(procedureId))
                                .switchIfEmpty(Mono.error(t));
                    }

                    // For IDX/UNKNOWN we want the retryWhen to handle it; for NOT_UNIQUE we fail fast.
                    return Mono.error(t);
                });

    }

    private Throwable maybeWrapAsExhausted(Throwable t) {
        UniqueViolationClassifier.Kind k = uniqueViolationClassifier.classify(t);
        if (k == UniqueViolationClassifier.Kind.IDX || k == UniqueViolationClassifier.Kind.UNKNOWN) {
            return new IndexReservationExhaustedException("Too many collisions while reserving index", t);
        }
        return t;
    }

}

