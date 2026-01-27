package es.in2.issuer.backend.statusList.application;

import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.spi.CredentialStatusAllocator;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


import static java.util.Objects.requireNonNull;

@Component
@RequiredArgsConstructor
public class StatusListAllocator implements CredentialStatusAllocator {
    private final StatusListWorkflow statusListWorkflow;

    @Override
    public Mono<CredentialStatus> allocate(String procedureId, String token) {
        requireNonNull(procedureId, "procedureId cannot be null");

        return statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, procedureId, token)
                .map(entry -> CredentialStatus.builder()
                        .id(entry.id())
                        .type(entry.type())
                        .statusPurpose(entry.statusPurpose().value())
                        .statusListIndex(String.valueOf(entry.statusListIndex()))
                        .statusListCredential(entry.statusListCredential())
                        .build());
    }
}

