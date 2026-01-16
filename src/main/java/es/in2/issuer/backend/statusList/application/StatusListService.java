package es.in2.issuer.backend.statusList.application;

import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import es.in2.issuer.backend.statusList.domain.spi.StatusListProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

import static java.util.Objects.requireNonNull;

@Service
@RequiredArgsConstructor
public class StatusListService {

    private final StatusListProvider statusListProvider;

    /**
     * Internal usage by Backoffice/OID4VCI: allocate a StatusListEntry (credentialStatus pointer)
     * to be embedded into the issued VC.
     */
    public Mono<StatusListEntry> allocateEntry(String issuerId, StatusPurpose purpose, String procedureId, String token) {
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(purpose, "purpose cannot be null");
        return statusListProvider.allocateEntry(issuerId, purpose, procedureId, token);
    }

    public Mono<String> getSignedStatusListCredential(Long listId) {
        requireNonNull(listId, "listId cannot be null");
        return statusListProvider.getSignedStatusListCredential(listId);
    }
}

