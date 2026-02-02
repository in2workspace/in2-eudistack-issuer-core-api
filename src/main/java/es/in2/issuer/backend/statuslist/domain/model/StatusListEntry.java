package es.in2.issuer.backend.statuslist.domain.model;

import lombok.Builder;

import static java.util.Objects.requireNonNull;

/**
 * W3C BitstringStatusListEntry (credentialStatus).
 * Pointer to a bit position inside a Status List Credential.
 */
@Builder
public record StatusListEntry(
        String id,
        String type,
        StatusPurpose statusPurpose,
        String statusListIndex,
        String statusListCredential
) {
}
