package es.in2.issuer.backend.statusList.infrastructure.adapter;

import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import es.in2.issuer.backend.statusList.domain.spi.StatusListIndexAllocator;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndexRow;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Reserves Status List indices using:
 * - Index allocation strategy (StatusListIndexAllocator)
 * - DB uniqueness constraint (statusListId, idx) for atomicity
 * - Retry with backoff on duplicate-key collisions
 *
 * If collisions are exhausted, it checks if the list is full and, if so,
 * creates a new list and retries on the new one.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BitstringStatusListIndexReservationService {

    private static final int CAPACITY_BITS = 131_072;

    private final StatusListIndexRepository statusListIndexRepository;
    private final StatusListIndexAllocator indexAllocator;
    private final BitstringStatusListLifecycleService lifecycleService;

    public Mono<StatusListIndexRow> reserveIndexWithRetry(
            Long statusListId,
            String procedureId,
            String issuerId,
            StatusPurpose purpose,
            String token
    ) {
        //todo
        log.info("reserveIndexWithRetry");
        requireNonNull(statusListId, "statusListId cannot be null");
        requireNonNull(procedureId, "procedureId cannot be null");
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(purpose, "purpose cannot be null");
        requireNonNull(token, "token cannot be null");

        return reserveOnSpecificList(statusListId, procedureId)
                .onErrorResume(IndexReservationExhaustedException.class, ex ->
                        statusListIndexRepository.countByStatusListId(statusListId)
                                .flatMap(count -> {
                                    if (count != null && count >= CAPACITY_BITS) {
                                        return lifecycleService.createNewList(issuerId, purpose, token)
                                                .flatMap(newList -> reserveOnSpecificList(newList.id(), procedureId));
                                    }
                                    return Mono.error(ex);
                                })
                );
    }

    public Mono<StatusListIndexRow> reserveOnSpecificList(Long statusListId, String procedureId) {
        //todo
        log.info("reserveOnSpecificList");
        requireNonNull(statusListId, "statusListId cannot be null");
        requireNonNull(procedureId, "procedureId cannot be null");

        int maxAttempts = 30;

        return Mono.defer(() -> tryReserveOnce(statusListId, procedureId))
                .retryWhen(
                        Retry.backoff(maxAttempts - 1, Duration.ofMillis(5))
                                .maxBackoff(Duration.ofMillis(100))
                                .filter(this::isDuplicateKey)
                                .doBeforeRetry(rs -> log.debug(
                                        "action=reserveStatusListIndex retryReason=duplicateKey statusListId={} procedureId={} attempt={}/{}",
                                        statusListId, procedureId, rs.totalRetries() + 2, maxAttempts
                                ))
                )
                .onErrorMap(this::maybeWrapAsExhausted);
    }

    private Mono<StatusListIndexRow> tryReserveOnce(Long statusListId, String procedureId) {
        //todo
        log.info("tryReserveOnce");
        int idx = indexAllocator.proposeIndex(CAPACITY_BITS);

        StatusListIndexRow row = new StatusListIndexRow(
                null,
                statusListId,
                idx,
                procedureId,
                Instant.now()
        );

        return statusListIndexRepository.save(row)
                .doOnNext(saved -> log.debug(
                        "Saved StatusListIndexRow: id={}, statusListId={}, idx={}, procedureId={}, createdAt={}",
                        saved.id(),
                        saved.statusListId(),
                        saved.idx(),
                        saved.procedureId(),
                        saved.createdAt()
                ))
                .doOnError(e -> log.error("Error saving StatusListIndexRow (statusListId={}, idx={}, procedureId={})",
                        statusListId, idx, procedureId, e
                ));
    }

    private boolean isDuplicateKey(Throwable t) {
        return t instanceof DataIntegrityViolationException;
    }

    private Throwable maybeWrapAsExhausted(Throwable t) {
        if (isDuplicateKey(t)) {
            return new IndexReservationExhaustedException("Too many collisions while reserving index", t);
        }
        return t;
    }

    static final class IndexReservationExhaustedException extends RuntimeException {
        IndexReservationExhaustedException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

