package es.in2.issuer.backend.statusList.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
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
    private final BitstringEncoder encoder = new BitstringEncoder();

    public Mono<StatusListRow> resolveRevocationCandidate(Long statusListId, Integer idx) {
        requireNonNull(statusListId, "statusListId cannot be null");
        requireNonNull(idx, "idx cannot be null");

        return statusListRepository.findById(statusListId)
                .switchIfEmpty(Mono.error(new StatusListNotFoundException(statusListId)))
                .flatMap(row ->
                        Mono.fromSupplier(() -> encoder.getBit(row.encodedList(), idx))
                                .flatMap(alreadyRevoked -> {
                                    if (alreadyRevoked) {
                                        log.debug("action=revokeStatusList result=alreadyRevoked statusListId={} idx={}", statusListId, idx);
                                        return Mono.empty();
                                    }
                                    return Mono.just(row);
                                })
                );
    }

    /**
     * Computes the new encoded list by setting the revocation bit to true and returns
     * a new StatusListRow instance reflecting the updated encoded list.
     *
     * This method does NOT persist anything.
     */
    public StatusListRow applyRevocationBit(StatusListRow currentRow, Integer idx) {
        requireNonNull(currentRow, "currentRow cannot be null");
        requireNonNull(idx, "idx cannot be null");

        String updatedEncoded = encoder.setBit(currentRow.encodedList(), idx, true);

        // Keep everything the same except the encoded list.
        // signedCredential remains as-is; provider will replace it during persistence.
        return new StatusListRow(
                currentRow.id(),
                currentRow.purpose(),
                updatedEncoded,
                currentRow.signedCredential(),
                currentRow.createdAt(),
                currentRow.updatedAt()
        );
    }
}
