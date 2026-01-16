package es.in2.issuer.backend.statusList.domain.spi;


import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Internal SPI to manage Status Lists with pluggable implementations
 * (Bitstring now, SD-JWT in the future).
 */
public interface StatusListProvider {

    /**
     * Allocates a new CredentialStatus (credentialStatus pointer) for a credential issuance flow.
     * The implementation is responsible for selecting/creating a Status List as needed.
     */
    Mono<StatusListEntry> allocateEntry(String issuerId, StatusPurpose purpose, String procedureId, String token);

    /**
     * Builds the Status List Credential payload to be returned by GET /api/v1/status-list/{listId}.
     * This method returns a JSON-like structure ready to be serialized.
     */
    Mono<Map<String, Object>> buildStatusListCredential(Long listId);

    /**
     *
     */
    Mono<String> getSignedStatusListCredential(Long listId);

    /**
     * Revokes a credential by setting the corresponding bit to 1 in the Status List.
     */
    Mono<Void> revoke(String procedureId, String token);

}
