package es.in2.issuer.backend.statusList.infrastructure.adapter;


import es.in2.issuer.backend.statusList.domain.exception.*;
import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import es.in2.issuer.backend.statusList.domain.spi.StatusListProvider;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statusList.infrastructure.repository.StatusListRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import static java.util.Objects.requireNonNull;

/**
 * Bitstring implementation of StatusListProvider.
 *
 * Responsibilities:
 * - Pick or create a Status List (status_list).
 * - Reserve indices atomically in DB (status_list_index) using UNIQUE constraints + retry.
 * - Revoke a credential by setting its bit to 1 in encodedList.
 * - Return Status List Credential payload for the GET endpoint.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BitstringStatusListProvider implements StatusListProvider {

    private final StatusListRepository statusListRepository;
    private final StatusListIndexRepository statusListIndexRepository;
    private final BitstringStatusListCredentialBuilder statusListBuilder;
    private final BitstringStatusListLifecycleService statusListLifecycleService;
    private final BitstringStatusListRevocationService revocationService;
    private final BitstringStatusListIndexReservationService statusListIndexReservationService;

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
                .map(existingRow -> statusListBuilder.buildStatusListEntry(existingRow.statusListId(), existingRow.idx(), purpose))
                .switchIfEmpty(
                        statusListLifecycleService.pickListForAllocation(issuerId, purpose, token)
                                .flatMap(list -> statusListIndexReservationService.reserveIndexWithRetry(list.id(), procedureId, issuerId, purpose, token))
                                .map(reservedIndex -> statusListBuilder.buildStatusListEntry(reservedIndex.statusListId(), reservedIndex.idx(), purpose))
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
                    return revocationService.revokeWithRetry(listIndex.statusListId(), listIndex.idx(), token);
                })
                .doOnSuccess(v -> log.info("action=revokeStatusList status=completed procedureId={}", procedureId))
                .doOnError(e -> log.warn("action=revokeStatusList status=failed procedureId={} error={}", procedureId, e.toString()));
    }

}

