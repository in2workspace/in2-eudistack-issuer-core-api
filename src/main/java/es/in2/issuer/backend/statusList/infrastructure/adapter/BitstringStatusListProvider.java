package es.in2.issuer.backend.statusList.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureConfiguration;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.statusList.domain.exception.*;
import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import es.in2.issuer.backend.statusList.domain.spi.StatusListIndexAllocator;
import es.in2.issuer.backend.statusList.domain.spi.StatusListProvider;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndexRow;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRow;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Bitstring implementation of StatusListProvider.
 *
 * Responsibilities:
 * - Pick or create a Status List (status_list).
 * - Propose candidate indices using StatusListIndexAllocator.
 * - Reserve indices atomically in DB (status_list_index) using UNIQUE constraints + retry.
 * - Revoke a credential by setting its bit to 1 in encodedList.
 * - Build the Status List Credential payload for the GET endpoint.
 */
@Slf4j
@Component
public class BitstringStatusListProvider implements StatusListProvider {

    private static final int CAPACITY_BITS = 131_072; // 16KB * 8
    private static final double NEW_LIST_THRESHOLD = 0.80;
    private static final String ENTRY_TYPE = "BitstringStatusListEntry";
    private static final String STATUS_LIST_CREDENTIAL_TYPE = "BitstringStatusListCredential";
    private static final String STATUS_LIST_SUBJECT_TYPE = "BitstringStatusList";
    private static final String VC_TYPE = "VerifiableCredential";

    private final StatusListRepository statusListRepository;
    private final StatusListIndexRepository statusListIndexRepository;
    private final StatusListIndexAllocator indexAllocator;
    private final RemoteSignatureService remoteSignatureService;
    private final ObjectMapper objectMapper;
    private final AppConfig appConfig;

    private final BitstringEncoder encoder = new BitstringEncoder();

    public BitstringStatusListProvider(
            StatusListRepository statusListRepository,
            StatusListIndexRepository statusListIndexRepository,
            StatusListIndexAllocator indexAllocator,
            RemoteSignatureService remoteSignatureService,
            ObjectMapper objectMapper,
            AppConfig appConfig
    ) {
        this.statusListRepository = requireNonNull(statusListRepository);
        this.statusListIndexRepository = requireNonNull(statusListIndexRepository);
        this.indexAllocator = requireNonNull(indexAllocator);
        this.remoteSignatureService = requireNonNull(remoteSignatureService);
        this.objectMapper = requireNonNull(objectMapper);
        this.appConfig = requireNonNull(appConfig);
    }

    @Override
    public Mono<String> getSignedStatusListCredential(Long listId) {
        requireNonNull(listId, "listId cannot be null");

        return statusListRepository.findById(listId)
                .switchIfEmpty(Mono.error(new StatusListNotFoundException(listId)))
                .flatMap(row -> {
                    String signed = row.signedCredential();
                    if (signed == null || signed.isBlank()) {
                        return Mono.error(new SignedStatusListCredentialNotAvailableException(listId));
                    }
                    return Mono.just(signed);
                });
    }

    @Override
    public Mono<StatusListEntry> allocateEntry(String issuerId, StatusPurpose purpose, String procedureId, String token) {
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(purpose, "purpose cannot be null");
        requireNonNull(procedureId, "procedureId cannot be null");
        requireNonNull(token, "token cannot be null");

        log.debug(
                "action=allocateStatusListEntry step=started issuerId={} purpose={} procedureId={}",
                issuerId, purpose, procedureId
        );

        // If the credential was already allocated, return the existing mapping (idempotent behavior).
        // todo consider finding by purpose; will be needed if new purposes are added in the future
        return statusListIndexRepository.findByProcedureId(procedureId)
                .doOnNext(existing -> log.debug(
                        "action=allocateStatusListEntry step=idempotentHit procedureId={} statusListId={} idx={}",
                        procedureId, existing.statusListId(), existing.idx()
                ))
                .map(existingRow -> buildEntry(existingRow.statusListId(), existingRow.idx(), purpose))
                .switchIfEmpty(
                        pickListForAllocation(issuerId, purpose, token)
                                .flatMap(list -> reserveIndexWithRetry(list.id(), procedureId, issuerId, purpose, token))
                                .map(reservedIndex -> buildEntry(reservedIndex.statusListId(), reservedIndex.idx(), purpose))
                )
                .doOnSuccess(entry -> log.info(
                        "action=allocateStatusListEntry status=completed issuerId={} purpose={} procedureId={} statusListCredential={} idx={}",
                        issuerId, purpose, procedureId, entry.statusListCredential(), entry.statusListIndex()
                ))
                .doOnError(e -> log.warn(
                        "action=allocateStatusListEntry status=failed issuerId={} purpose={} procedureId={} error={}",
                        issuerId, purpose, procedureId, e.toString()
                ));
    }

    @Override
    public Mono<Map<String, Object>> buildStatusListCredential(Long listId) {
        requireNonNull(listId, "listId cannot be null");

        return statusListRepository.findById(listId)
                .switchIfEmpty(Mono.error(new StatusListNotFoundException(listId)))
                .map(row -> {
                    String listUrl = buildListUrl(row.id());

                    Map<String, Object> credentialSubject = new LinkedHashMap<>();
                    credentialSubject.put("type", STATUS_LIST_SUBJECT_TYPE);
                    credentialSubject.put("statusPurpose", row.purpose());
                    credentialSubject.put("encodedList", row.encodedList());

                    Map<String, Object> vc = new LinkedHashMap<>();
                    vc.put("@context", new Object[]{
                            "https://www.w3.org/ns/credentials/v2",
                            "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld"
                    });
                    vc.put("id", listUrl);
                    vc.put("type", new Object[]{VC_TYPE, STATUS_LIST_CREDENTIAL_TYPE});
                    vc.put("issuer", row.issuerId());

                    // validFrom?

                    vc.put("credentialSubject", credentialSubject);
                    return vc;
                });
    }

    @Override
    public Mono<Void> revoke(String procedureId, String token) {
        requireNonNull(procedureId, "procedureId cannot be null");
        requireNonNull(token, "token cannot be null");

        log.info("action=revokeStatusList status=started procedureId={}", procedureId);

        return statusListIndexRepository.findByProcedureId(procedureId)
                .switchIfEmpty(Mono.error(new StatusListIndexNotFoundException(procedureId)))
                .flatMap(listIndex -> {
                    log.debug(
                            "action=revokeStatusList step=indexResolved procedureId={} statusListId={} idx={}",
                            procedureId, listIndex.statusListId(), listIndex.idx()
                    );
                    return revokeWithRetry(listIndex.statusListId(), listIndex.idx(), token);
                })
                .doOnSuccess(v -> log.info("action=revokeStatusList status=completed procedureId={}", procedureId))
                .doOnError(e -> log.warn("action=revokeStatusList status=failed procedureId={} error={}", procedureId, e.toString()));
    }


    private Mono<Void> revokeWithRetry(Long statusListId, Integer idx, String token) {

        int maxAttempts = 5;

        return Mono.defer(() -> revokeOnce(statusListId, idx, token))
                .retryWhen(
                        Retry
                                .backoff(maxAttempts - 1, Duration.ofMillis(50))
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
                .flatMap(row ->
                        isAlreadyRevoked(row, idx)
                                .flatMap(alreadyRevoked -> {
                                    if (alreadyRevoked) {
                                        log.debug("action=revokeStatusList result=alreadyRevoked statusListId={} idx={}", statusListId, idx);
                                        return Mono.empty();
                                    }

                                    String updatedEncoded = encodeRevocation(row, idx);

                                    return signUpdatedStatusListCredential(row, updatedEncoded, token)
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

    private Mono<String> signUpdatedStatusListCredential(StatusListRow row, String updatedEncoded, String token) {
        return Mono.fromSupplier(() -> buildUnsignedCredential(
                        row.id(),
                        row.issuerId(),
                        row.purpose(),
                        updatedEncoded
                ))
                .flatMap(this::toSignatureRequestSafe)
                .flatMap(req -> remoteSignatureService.signDocument(req, token))
                .onErrorMap(ex -> new RemoteSignatureException("Remote signature failed for statusListId=" + row.id(), ex))
                .map(this::extractJwtSafe);
    }

    private Mono<SignatureRequest> toSignatureRequestSafe(Map<String, Object> payload) {
        return Mono.fromCallable(() -> {
            String json = objectMapper.writeValueAsString(payload);

            SignatureConfiguration config = SignatureConfiguration.builder()
                    .type(SignatureType.JADES)
                    .parameters(java.util.Collections.emptyMap())
                    .build();

            return SignatureRequest.builder()
                    .configuration(config)
                    .data(json)
                    .build();
        }).onErrorMap(com.fasterxml.jackson.core.JsonProcessingException.class,
                ex -> new StatusListCredentialSerializationException(ex)
        );
    }

    private String extractJwtSafe(SignedData signedData) {
        if (signedData == null || signedData.data() == null || signedData.data().isBlank()) {
            throw new RemoteSignatureException("Remote signature failed: empty response");
        }
        return signedData.data();
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


    // maybe repeated?
    private Mono<SignatureRequest> toSignatureRequest(Map<String, Object> payload) {
        return Mono.fromCallable(() -> {
            String json = objectMapper.writeValueAsString(payload);

            SignatureConfiguration config = SignatureConfiguration.builder()
                    .type(SignatureType.JADES)
                    .parameters(Collections.emptyMap())
                    .build();

            return SignatureRequest.builder()
                    .configuration(config)
                    .data(json)
                    .build();
        });
    }

    // todo maybe reapeated?
    private String extractJwtFromSignedData(SignedData signedData, Long statusListId) {
        if (signedData == null || signedData.data() == null || signedData.data().isBlank()) {
            throw new RemoteSignatureException("Remote signer returned empty SignedData for statusListId=" + statusListId);
        }
        return signedData.data();
    }

    private static final class OptimisticUpdateException extends RuntimeException {
        private OptimisticUpdateException(String message) {
            super(message);
        }
    }


    private Map<String, Object> buildUnsignedCredential(
            Long listId,
            String issuerId,
            String purpose,
            String encodedList
    ) {
        String listUrl = buildListUrl(listId);

        Map<String, Object> credentialSubject = new LinkedHashMap<>();
        credentialSubject.put("type", STATUS_LIST_SUBJECT_TYPE);
        credentialSubject.put("statusPurpose", purpose);
        credentialSubject.put("encodedList", encodedList);

        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("@context", new Object[]{
                "https://www.w3.org/ns/credentials/v2",
                "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld"
        });
        vc.put("id", listUrl);
        vc.put("type", new Object[]{VC_TYPE, STATUS_LIST_CREDENTIAL_TYPE});
        vc.put("issuer", issuerId);
        vc.put("credentialSubject", credentialSubject);
        return vc;
    }

    // ----------------------
    // Internal helpers
    // ----------------------

    private Mono<StatusListRow> findOrCreateLatestList(String issuerId, StatusPurpose purpose, String token) {
        // Since we won't have many rows (probably only 1), we don't need and index for this
        return statusListRepository.findLatestByIssuerAndPurpose(issuerId, purpose.value())
                .switchIfEmpty(createNewList(issuerId, purpose, token));
    }

    private Mono<StatusListRow> createNewList(String issuerId, StatusPurpose purpose, String token) {
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
                    log.info("action=createStatusList step=inserted statusListId={} issuerId={} purpose={}", saved.id(), issuerId, purpose);

                    Map<String, Object> payload = buildUnsignedCredential(
                            saved.id(),
                            saved.issuerId(),
                            saved.purpose(),
                            saved.encodedList()
                    );

                    return toSignatureRequest(payload)
                            .flatMap(req -> remoteSignatureService.signDocument(req, token))
                            .onErrorMap(ex -> new RemoteSignatureException("Remote signature failed for statusListId=" + saved.id(), ex))
                            .flatMap(signedData -> {
                                String signedJwt = extractJwtFromSignedData(signedData, saved.id());
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




    private Mono<StatusListRow> pickListForAllocation(String issuerId, StatusPurpose purpose, String token) {
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
     * Reserves an index for a credential on a given status list using:
     * - random proposeIndex()
     * - DB UNIQUE(status_list_id, idx) + retry on DataIntegrityViolationException
     *
     * If it keeps failing, it checks whether the list is full and creates a new list if needed.
     */
    private Mono<StatusListIndexRow> reserveIndexWithRetry(
            Long statusListId,
            String procedureId,
            String issuerId,
            StatusPurpose purpose,
            String token
    ) {
        // First attempt tries on the provided list; if the list is full we create a new one and retry.
        return reserveOnSpecificList(statusListId, procedureId)
                .onErrorResume(IndexReservationExhaustedException.class, ex ->
                        statusListIndexRepository.countByStatusListId(statusListId)
                                .flatMap(count -> {
                                    if (count != null && count >= CAPACITY_BITS) {
                                        return createNewList(issuerId, purpose, token)
                                                .flatMap(newList -> reserveOnSpecificList(newList.id(), procedureId));
                                    }
                                    return Mono.error(ex);
                                })
                );
    }

    private Mono<StatusListIndexRow> reserveOnSpecificList(Long statusListId, String procedureId) {
        // We keep this small; if collisions spike, we treat it as "exhausted".
        int maxAttempts = 30; //0.001% de probabilitat de col·lisió

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
        int idx = indexAllocator.proposeIndex(CAPACITY_BITS);
        StatusListIndexRow row = new StatusListIndexRow(
                null, // autoincrement id in status_list_index
                statusListId,
                idx,
                procedureId,
                Instant.now()
        );
        return statusListIndexRepository.save(row);
    }

    private boolean isDuplicateKey(Throwable t) {
        // Spring usually wraps unique constraint violations as DataIntegrityViolationException.
        return t instanceof DataIntegrityViolationException;
    }

    private Throwable maybeWrapAsExhausted(Throwable t) {
        if (isDuplicateKey(t)) {
            return new IndexReservationExhaustedException("Too many collisions while reserving index", t);
        }
        return t;
    }

    private StatusListEntry buildEntry(Long listId, Integer idx, StatusPurpose purpose) {
        if (idx == null) {
            throw new IllegalStateException("Invariant violation: cannot build StatusListEntry with null index (listId=" + listId + ")");
        }
        String listUrl = buildListUrl(listId);
        String id = listUrl + "#" + idx;

        return StatusListEntry.builder()
                .id(id)
                .type(ENTRY_TYPE)
                .statusPurpose(purpose)
                .statusListIndex(String.valueOf(idx))
                .statusListCredential(listUrl)
                .build();
    }

    private String buildListUrl(Long listId) {
        return appConfig.getIssuerBackendUrl() + "/api/v1/status-list" + "/" + listId;
    }

    // todo exception for exception global exception handler?
    private static final class IndexReservationExhaustedException extends RuntimeException {
        private IndexReservationExhaustedException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

