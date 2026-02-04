package es.in2.issuer.backend.statuslist.domain.model;

import lombok.Builder;

// Legacy model used to handle status list indexes with a PlainListEntry credentialStatus.
// TODO Remove once the last credential of this type expires in DOME.
@Builder
public record StatusListEntry(
        String id,
        String type,
        StatusPurpose statusPurpose,
        String statusListIndex,
        String statusListCredential
) {
}
