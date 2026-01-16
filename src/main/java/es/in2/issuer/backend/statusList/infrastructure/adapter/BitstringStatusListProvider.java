package es.in2.issuer.backend.statusList.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureConfiguration;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import es.in2.issuer.backend.statusList.domain.spi.StatusListIndexAllocator;
import es.in2.issuer.backend.statusList.domain.spi.StatusListProvider;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndexRow;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRow;
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

    private final BitstringEncoder encoder = new BitstringEncoder();

    /**
     * Example: "https://issuer.example.org/api/v1/status-list"
     * Final credential URL becomes: {statusListBaseUrl}/{listId}
     */
    private final String statusListBaseUrl;

    public BitstringStatusListProvider(
            StatusListRepository statusListRepository,
            StatusListIndexRepository statusListIndexRepository,
            StatusListIndexAllocator indexAllocator,
            String statusListBaseUrl,
            RemoteSignatureService remoteSignatureService,
            ObjectMapper objectMapper,
            String signatureToken
    ) {
        this.statusListRepository = requireNonNull(statusListRepository);
        this.statusListIndexRepository = requireNonNull(statusListIndexRepository);
        this.indexAllocator = requireNonNull(indexAllocator);
        this.statusListBaseUrl = requireNonNull(statusListBaseUrl);
        this.remoteSignatureService = requireNonNull(remoteSignatureService);
        this.objectMapper = requireNonNull(objectMapper);
    }

    @Override
    public Mono<String> getSignedStatusListCredential(Long listId) {
        requireNonNull(listId, "listId cannot be null");

        return statusListRepository.findById(listId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Status list not found: " + listId)))
                .flatMap(row -> {
                    String signed = row.signedCredential();
                    if (signed == null || signed.isBlank()) {
                        return Mono.error(new IllegalStateException("Signed credential not available for status list: " + listId));
                    }
                    return Mono.just(signed);
                });
    }


    @Override
    public Mono<StatusListEntry> allocateEntry(String issuerId, StatusPurpose purpose, String procedureId, String token) {
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(purpose, "purpose cannot be null");
        requireNonNull(procedureId, "procedureId cannot be null");

        // If the credential was already allocated, return the existing mapping (idempotent behavior).
        // todo consider finding by purpose; will be needed if new purposes are added in the future
        return statusListIndexRepository.findByprocedureId(procedureId)
                .map(existing -> buildEntry(existing.statusListId(), existing.idx(), purpose))
                .switchIfEmpty(
                        pickListForAllocation(issuerId, purpose, token)
                                .flatMap(list -> reserveIndexWithRetry(list.id(), procedureId, issuerId, purpose, token))
                                .map(reservation -> buildEntry(reservation.statusListId(), reservation.idx(), purpose))
                );
    }

    @Override
    public Mono<Map<String, Object>> buildStatusListCredential(Long listId) {
        requireNonNull(listId, "listId cannot be null");

        return statusListRepository.findById(listId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Status list not found: " + listId)))
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

                    // Optional: you can add "validFrom" based on createdAt if your ecosystem expects it.
                    // vc.put("validFrom", row.createdAt().toString());

                    vc.put("credentialSubject", credentialSubject);
                    return vc;
                });
    }

    @Override
    public Mono<Void> revoke(String procedureId, String token) {
        requireNonNull(procedureId, "procedureId cannot be null");
        requireNonNull(token, "token cannot be null");

        // todo consider finding by purpose; will be needed if new purposes are added in the future
        return statusListIndexRepository.findByprocedureId(procedureId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("No status list mapping found for credential: " + procedureId)))
                .flatMap(mapping -> revokeWithRetry(mapping.statusListId(), mapping.idx(), token))
                .then();
    }

    private Mono<Void> revokeWithRetry(Long statusListId, Integer idx, String token) {
        int maxAttempts = 5;

        return Mono.defer(() -> revokeOnce(statusListId, idx, token))
                .retryWhen(
                        Retry.max(maxAttempts - 1)
                                .filter(t -> t instanceof OptimisticUpdateException)
                );
    }

    private Mono<Void> revokeOnce(Long statusListId, Integer idx, String token) {
        return statusListRepository.findById(statusListId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Status list not found: " + statusListId)))
                .flatMap(currentRow -> {
                    String updatedEncoded = encoder.setBit(currentRow.encodedList(), idx, true);

                    StatusListRow rowForSigning = new StatusListRow(
                            currentRow.id(),
                            currentRow.issuerId(),
                            currentRow.purpose(),
                            updatedEncoded,
                            currentRow.signedCredential(),
                            currentRow.createdAt(),
                            currentRow.updatedAt()
                    );

                    Map<String, Object> payload = buildUnsignedCredential(rowForSigning);

                    return toSignatureRequest(payload)
                            .flatMap(req -> remoteSignatureService.signDocument(req, token))
                            .flatMap(signedData -> {
                                String signedJwt = extractJwt(signedData);
                                Instant newUpdatedAt = Instant.now();

                                return statusListRepository.updateSignedAndEncodedIfUnchanged(
                                                currentRow.id(),
                                                updatedEncoded,
                                                signedJwt,
                                                newUpdatedAt,
                                                currentRow.updatedAt()
                                        )
                                        .flatMap(rows -> {
                                            if (rows != null && rows == 1) {
                                                return Mono.empty();
                                            }
                                            return Mono.error(new OptimisticUpdateException(
                                                    "Concurrent update detected for status list: " + currentRow.id()
                                            ));
                                        });
                            });
                });
    }

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

    private String extractJwt(SignedData signedData) {
        if (signedData == null || signedData.data() == null || signedData.data().isBlank()) {
            throw new IllegalStateException("Remote signer returned empty SignedData");
        }
        return signedData.data();
    }

    private static final class OptimisticUpdateException extends RuntimeException {
        private OptimisticUpdateException(String message) {
            super(message);
        }
    }


    private Map<String, Object> buildUnsignedCredential(StatusListRow row) {
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
        vc.put("credentialSubject", credentialSubject);
        return vc;
    }

    // ----------------------
    // Internal helpers
    // ----------------------

    private Mono<StatusListRow> findOrCreateLatestList(String issuerId, StatusPurpose purpose, String token) {
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

        return statusListRepository.save(rowToInsert)
                .flatMap(saved -> {
                    Map<String, Object> payload = buildUnsignedCredential(saved);

                    return toSignatureRequest(payload)
                            .flatMap(req -> remoteSignatureService.signDocument(req, token))
                            .flatMap(signedData -> {
                                String signedJwt = extractJwt(signedData);
                                Instant updatedAt = Instant.now();

                                return statusListRepository.updateSignedCredential(saved.id(), signedJwt, updatedAt)
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
                                            return Mono.error(new IllegalStateException(
                                                    "Failed to update signed credential for new status list: " + saved.id()
                                            ));
                                        });
                            })
                            .onErrorResume(ex ->
                                    statusListRepository.deleteById(saved.id()).then(Mono.error(ex))
                            );
                });
    }




    private Mono<StatusListRow> pickListForAllocation(String issuerId, StatusPurpose purpose, String token) {
        return findOrCreateLatestList(issuerId, purpose, token)
                .flatMap(list ->
                        statusListIndexRepository.countByStatusListId(list.id())
                                .flatMap(count -> {
                                    long threshold = (long) Math.floor(CAPACITY_BITS * NEW_LIST_THRESHOLD);
                                    if (count != null && count >= threshold) {
                                        return createNewList(issuerId, purpose, token);
                                    }
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
        int maxAttempts = 100;

        return Mono.defer(() -> tryReserveOnce(statusListId, procedureId))
                .retryWhen(
                        Retry.fixedDelay(maxAttempts - 1, Duration.ofMillis(0))
                                .filter(this::isDuplicateKey)
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
            throw new IllegalStateException("Allocated idx cannot be null");
        }
        String listUrl = buildListUrl(listId);
        String id = listUrl + "#" + idx;

        // Assuming your StatusListEntry is a record with builder or canonical ctor.
        // Adjust to your exact constructor/builder.
        return StatusListEntry.builder()
                .id(id)
                .type(ENTRY_TYPE)
                .statusPurpose(purpose)
                .statusListIndex(String.valueOf(idx))
                .statusListCredential(listUrl)
                .build();
    }

    private String buildListUrl(Long listId) {
        String base = statusListBaseUrl.endsWith("/") ? statusListBaseUrl.substring(0, statusListBaseUrl.length() - 1) : statusListBaseUrl;
        return base + "/" + listId;
    }

    // todo exception for exception global exception handler?
    private static final class IndexReservationExhaustedException extends RuntimeException {
        private IndexReservationExhaustedException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

