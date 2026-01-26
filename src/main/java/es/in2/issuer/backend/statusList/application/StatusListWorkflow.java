package es.in2.issuer.backend.statusList.application;

import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import es.in2.issuer.backend.statusList.domain.spi.StatusListProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static java.util.Objects.requireNonNull;

//todo maybe name service, since allocateEntry is not a use-case
@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListWorkflow {

    private final StatusListProvider statusListProvider;

    /**
     * Internal usage by Backoffice/OID4VCI: allocate a StatusListEntry (credentialStatus pointer)
     * to be embedded into the issued VC.
     */
    public Mono<StatusListEntry> allocateEntry(String issuerId, StatusPurpose purpose, String procedureId, String token) {
        //todo remove
        log.info("StatusListService - allocateEntry, issuerId: {}, purpose: {}, procedureId: {}, token: {}", issuerId, purpose, procedureId, token);
        log.info(
                "action=allocateStatusListEntry status=started issuerId={} purpose={} procedureId={}",
                issuerId, purpose, procedureId
        );
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(purpose, "purpose cannot be null");
        return statusListProvider.allocateEntry(issuerId, purpose, procedureId, token)
                .doOnSuccess(entry -> log.info(
                        "action=allocateStatusListEntry status=completed issuerId={} purpose={} procedureId={} listId={} idx={}",
                        issuerId, purpose, procedureId,
                        extractListId(entry), entry.statusListIndex()
                ))
                .doOnError(e -> log.warn(
                        "action=allocateStatusListEntry status=failed issuerId={} purpose={} procedureId={} error={}",
                        issuerId, purpose, procedureId, e.toString()
                ));
    }

    public Mono<String> getSignedStatusListCredential(Long listId) {
        requireNonNull(listId, "listId cannot be null");
        return statusListProvider.getSignedStatusListCredential(listId);
    }


    private String extractListId(StatusListEntry entry) {
        String cred = entry.statusListCredential();
        if (cred == null) return "unknown";
        int lastSlash = cred.lastIndexOf('/');
        return lastSlash >= 0 ? cred.substring(lastSlash + 1) : "unknown";
    }
}

