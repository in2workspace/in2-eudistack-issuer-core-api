package es.in2.issuer.backend.statusList.application;

import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import es.in2.issuer.backend.statusList.domain.spi.StatusListProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static java.util.Objects.requireNonNull;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListWorkflow {

    private final StatusListProvider statusListProvider;

    public Mono<StatusListEntry> allocateEntry(StatusPurpose purpose, String procedureId, String token) {
        log.info("StatusListService - allocateEntry, purpose: {}, procedureId: {}, token: {}", purpose, procedureId, token);
        log.info(
                "action=allocateStatusListEntry status=started purpose={} procedureId={}",
                purpose, procedureId
        );
        requireNonNull(purpose, "purpose cannot be null");

        return statusListProvider.allocateEntry(purpose, procedureId, token)
                .doOnSuccess(entry -> log.info(
                        "action=allocateStatusListEntry status=completed purpose={} procedureId={} listId={} idx={}",
                        purpose, procedureId,
                        extractListId(entry), entry.statusListIndex()
                ))
                .doOnError(e -> log.warn(
                        "action=allocateStatusListEntry status=failed purpose={} procedureId={} error={}",
                        purpose, procedureId, e.toString()
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

