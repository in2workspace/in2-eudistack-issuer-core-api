package es.in2.issuer.backend.statuslist.domain.spi;


import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import reactor.core.publisher.Mono;

/**
 * Internal SPI to manage Status Lists with pluggable implementations
 * (Bitstring now, SD-JWT in the future).
 */
public interface StatusListProvider {

    /**
     * Allocates a new CredentialStatus (credentialStatus pointer) for a credential issuance flow.
     * The implementation is responsible for selecting/creating a Status List as needed.
     */
    Mono<StatusListEntry> allocateEntry(StatusPurpose purpose, String procedureId, String token);

    /**
     * Returns de VC JWT of the StatusListCredential
     */
    Mono<String> getSignedStatusListCredential(Long listId);

    /**
     * Revokes a credential by setting the corresponding bit to 1 in the Status List.
     */
    Mono<Void> revoke(String procedureId, String token);

}
