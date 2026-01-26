package es.in2.issuer.backend.statusList.infrastructure.adapter;

import es.in2.issuer.backend.statusList.domain.exception.ConcurrentStatusListUpdateException;
import es.in2.issuer.backend.statusList.domain.exception.StatusListNotFoundException;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Service responsible for revoking credentials in a Status List.
 *
 * Handles:
 * - Bitstring manipulation (setting revocation bit)
 * - Optimistic locking for concurrent updates
 * - Signing updated credentials
 * - Persistence with retry logic
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BitstringStatusListRevocationService {

    private final StatusListRepository statusListRepository;
    private final BitstringStatusListCredentialBuilder statusListBuilder;
    private final StatusListSigner statusListSigner;

    private final BitstringEncoder encoder = new BitstringEncoder();

    /**
     * Revokes a credential at a specific index in a status list.
     * Uses optimistic locking with retry to handle concurrent updates.
     *
     * @param statusListId the status list ID
     * @param idx the index to revoke
     * @param token authentication token for signing
     * @return Mono that completes when revocation is successful
     */
    public Mono<Void> revokeWithRetry(Long statusListId, Integer idx, String token) {
        requireNonNull(statusListId, "statusListId cannot be null");
        requireNonNull(idx, "idx cannot be null");
        requireNonNull(token, "token cannot be null");

        int maxAttempts = 5;

        return Mono.defer(() -> revokeOnce(statusListId, idx, token))
                .retryWhen(
                        Retry.backoff(maxAttempts - 1, Duration.ofMillis(50))
                                .maxBackoff(Duration.ofSeconds(1))
                                .jitter(0.2)
                                .filter(OptimisticUpdateException.class::isInstance)
                                .doBeforeRetry(rs -> log.debug(
                                        "action=revokeStatusList retryReason=optimisticLock statusListId={} idx={} attempt={}/{}",
                                        statusListId, idx, rs.totalRetries() + 1, maxAttempts
                                ))
                                .onRetryExhaustedThrow((spec, signal) ->
                                        new ConcurrentStatusListUpdateException(statusListId, idx, signal.failure())
                                )
                )
                .doOnSuccess(v -> log.debug("action=revokeStatusList step=revoked statusListId={} idx={}", statusListId, idx))
                .doOnError(e -> log.warn("action=revokeStatusList step=revocationFailed statusListId={} idx={} error={}",
                        statusListId, idx, e.toString()));
    }

    private Mono<Void> revokeOnce(Long statusListId, Integer idx, String token) {
        return findStatusListOrFail(statusListId)
                .flatMap(row -> isAlreadyRevoked(row, idx)
                        .flatMap(alreadyRevoked -> {
                            if (alreadyRevoked) {
                                log.debug("action=revokeStatusList result=alreadyRevoked statusListId={} idx={}", statusListId, idx);
                                return Mono.empty();
                            }

                            String updatedEncoded = encodeRevocation(row, idx);
                            return signUpdatedCredential(row, updatedEncoded, token)
                                    .flatMap(signedJwt -> persistOptimisticUpdate(row, updatedEncoded, signedJwt));
                        })
                );
    }

    private Mono<StatusListRow> findStatusListOrFail(Long statusListId) {
        return statusListRepository.findById(statusListId)
                .switchIfEmpty(Mono.error(new StatusListNotFoundException(statusListId)));
    }

    private Mono<Boolean> isAlreadyRevoked(StatusListRow row, Integer idx) {
        return Mono.fromSupplier(() -> encoder.getBit(row.encodedList(), idx));
    }

    private String encodeRevocation(StatusListRow row, Integer idx) {
        return encoder.setBit(row.encodedList(), idx, true);
    }

    private Mono<String> signUpdatedCredential(StatusListRow row, String updatedEncoded, String token) {
        Map<String, Object> payload = statusListBuilder.buildUnsigned(
                row.id(),
                row.issuerId(),
                row.purpose(),
                updatedEncoded
        );
        return statusListSigner.signPayload(payload, token, row.id());
    }

    private Mono<Void> persistOptimisticUpdate(StatusListRow currentRow, String updatedEncoded, String signedJwt) {
        return statusListRepository.updateSignedAndEncodedIfUnchanged(
                        currentRow.id(),
                        updatedEncoded,
                        signedJwt,
                        currentRow.updatedAt()
                )
                .flatMap(rows -> {
                    if (rows != null && rows == 1) {
                        log.debug("action=revokeStatusList result=updated statusListId={}", currentRow.id());
                        return Mono.empty();
                    }
                    return Mono.error(new OptimisticUpdateException(
                            "Concurrent update detected for status list: " + currentRow.id()
                    ));
                });
    }

    private static final class OptimisticUpdateException extends RuntimeException {
        private OptimisticUpdateException(String message) {
            super(message);
        }
    }
}
