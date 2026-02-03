package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import es.in2.issuer.backend.statuslist.domain.exception.IndexReservationExhaustedException;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListIndexAllocator;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListIndexReservation;
import es.in2.issuer.backend.statuslist.domain.model.UniqueConstraintKind;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import io.r2dbc.spi.R2dbcException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.CAPACITY_BITS;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

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
@Service
@RequiredArgsConstructor
public class BitstringStatusListIndexReservationService implements StatusListIndexReservation {

    private final StatusListIndexRepository statusListIndexRepository;
    private final StatusListIndexAllocator indexAllocator;

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
                                    UniqueConstraintKind k = classify(t);
                                    return k == UniqueConstraintKind.IDX || k == UniqueConstraintKind.UNKNOWN;
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
                    UniqueConstraintKind k = classify(t);
                    log.debug(
                            "action=tryReserveOnce constraintKind={} statusListId={} idx={} procedureId={}",
                            k, statusListId, idx, procedureId
                    );

                    if (k == UniqueConstraintKind.PROCEDURE) {
                        return statusListIndexRepository.findByProcedureId(UUID.fromString(procedureId))
                                .switchIfEmpty(Mono.error(t));
                    }

                    // For IDX/UNKNOWN we want the retryWhen to handle it; for NOT_UNIQUE we fail fast.
                    return Mono.error(t);
                });
    }

    private Throwable maybeWrapAsExhausted(Throwable t) {
        UniqueConstraintKind k = classify(t);
        if (k == UniqueConstraintKind.IDX || k == UniqueConstraintKind.UNKNOWN) {
            return new IndexReservationExhaustedException("Too many collisions while reserving index", t);
        }
        return t;
    }

    private boolean isUniqueViolation(Throwable t) {
        R2dbcException ex = findCause(t, R2dbcException.class);
        return ex != null && "23505".equals(ex.getSqlState());
    }

    private <T extends Throwable> T findCause(Throwable t, Class<T> type) {
        Throwable cur = t;
        while (cur != null) {
            if (type.isInstance(cur)) {
                return type.cast(cur);
            }
            cur = cur.getCause();
        }
        return null;
    }

    private static final Pattern UNIQUE_CONSTRAINT =
            Pattern.compile("unique constraint \"([^\"]+)\"");

    private String extractConstraintName(Throwable t) {
        R2dbcException ex = findCause(t, R2dbcException.class);
        if (ex == null || ex.getMessage() == null) {
            return null;
        }
        Matcher m = UNIQUE_CONSTRAINT.matcher(ex.getMessage());
        return m.find() ? m.group(1) : null;
    }

    private UniqueConstraintKind classify(Throwable t) {
        if (!isUniqueViolation(t)) {
            return UniqueConstraintKind.NOT_UNIQUE;
        }

        String name = extractConstraintName(t);
        if (name == null) {
            return UniqueConstraintKind.UNKNOWN;
        }

        if ("uq_status_list_index_list_id_idx".equals(name)) {
            return UniqueConstraintKind.IDX;
        }
        if ("uq_status_list_index_procedure_id".equals(name)) {
            return UniqueConstraintKind.PROCEDURE;
        }

        return UniqueConstraintKind.UNKNOWN;
    }

}

