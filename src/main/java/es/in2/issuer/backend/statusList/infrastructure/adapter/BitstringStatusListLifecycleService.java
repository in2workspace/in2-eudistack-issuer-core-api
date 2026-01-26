package es.in2.issuer.backend.statusList.infrastructure.adapter;

import es.in2.issuer.backend.statusList.domain.exception.StatusListSigningPersistenceException;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Handles Status List lifecycle for the Bitstring implementation:
 * - Find the latest list for an issuer + purpose
 * - Create and sign a new list when needed
 * - Apply the allocation policy (threshold-based rotation)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BitstringStatusListLifecycleService {

    private static final int CAPACITY_BITS = 131_072; // 16KB * 8
    private static final double NEW_LIST_THRESHOLD = 0.80;

    private final StatusListRepository statusListRepository;
    private final StatusListIndexRepository statusListIndexRepository;
    private final BitstringStatusListCredentialBuilder statusListBuilder;
    private final StatusListSigner statusListSigner;

    private final BitstringEncoder encoder = new BitstringEncoder();

    /**
     * Returns a Status List suitable for allocating a new entry.
     * If the latest list is beyond the configured threshold, a new list is created and returned.
     */
    public Mono<StatusListRow> pickListForAllocation(String issuerId, StatusPurpose purpose, String token) {
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(purpose, "purpose cannot be null");
        requireNonNull(token, "token cannot be null");

        long threshold = (long) Math.floor(CAPACITY_BITS * NEW_LIST_THRESHOLD);

        return findOrCreateLatestList(issuerId, purpose, token)
                .flatMap(list ->
                        statusListIndexRepository.countByStatusListId(list.id())
                                .flatMap(count -> {
                                    if (count != null && count >= threshold) {
                                        log.info(
                                                "action=allocateStatusListEntry step=thresholdReached issuerId={} purpose={} statusListId={} count={} threshold={} action=createNewList",
                                                issuerId, purpose, list.id(), count, threshold
                                        );
                                        return createNewList(issuerId, purpose, token);
                                    }

                                    log.debug(
                                            "action=allocateStatusListEntry step=reuseList issuerId={} purpose={} statusListId={} count={} threshold={}",
                                            issuerId, purpose, list.id(), count, threshold
                                    );
                                    return Mono.just(list);
                                })
                );
    }

    /**
     * Creates a new empty Status List, signs its credential, and persists the signed JWT.
     * If signing or persistence fails, it attempts to roll back by deleting the inserted row.
     */
    public Mono<StatusListRow> createNewList(String issuerId, StatusPurpose purpose, String token) {
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(purpose, "purpose cannot be null");
        requireNonNull(token, "token cannot be null");

        String emptyEncodedList = encoder.createEmptyEncodedList(CAPACITY_BITS);
        Instant now = Instant.now();

        StatusListRow rowToInsert = new StatusListRow(
                null,
                issuerId,
                purpose.value(),
                emptyEncodedList,
                null,
                now,
                now
        );

        log.info("action=createStatusList status=started issuerId={} purpose={}", issuerId, purpose);

        return statusListRepository.save(rowToInsert)
                .flatMap(saved -> {
                    log.info(
                            "action=createStatusList step=inserted statusListId={} issuerId={} purpose={}",
                            saved.id(), issuerId, purpose
                    );

                    Map<String, Object> payload = statusListBuilder.buildUnsigned(
                            saved.id(),
                            saved.issuerId(),
                            saved.purpose(),
                            saved.encodedList()
                    );

                    return statusListSigner.signPayload(payload, token, saved.id())
                            .flatMap(signedJwt -> {
                                Instant updatedAt = Instant.now();

                                return statusListRepository.updateSignedCredential(saved.id(), signedJwt)
                                        .flatMap(rows -> {
                                            if (rows != null && rows == 1) {
                                                return Mono.just(new StatusListRow(
                                                        saved.id(),
                                                        saved.issuerId(),
                                                        saved.purpose(),
                                                        saved.encodedList(),
                                                        signedJwt,
                                                        saved.createdAt(),
                                                        updatedAt
                                                ));
                                            }
                                            return Mono.error(new StatusListSigningPersistenceException(saved.id()));
                                        });
                            })
                            .onErrorResume(ex ->
                                    statusListRepository.deleteById(saved.id()).then(Mono.error(ex))
                            );
                });
    }

    private Mono<StatusListRow> findOrCreateLatestList(String issuerId, StatusPurpose purpose, String token) {
        // Since we won't have many rows (probably only 1), we don't need and index for this
        return statusListRepository.findLatestByIssuerAndPurpose(issuerId, purpose.value())
                .switchIfEmpty(createNewList(issuerId, purpose, token));
    }
}
