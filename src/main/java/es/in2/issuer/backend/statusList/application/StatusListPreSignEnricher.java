package es.in2.issuer.backend.statusList.application;

import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.spi.CredentialPreSignEnricher;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


import static java.util.Objects.requireNonNull;

@Component
@RequiredArgsConstructor
public class StatusListPreSignEnricher implements CredentialPreSignEnricher {
    private final StatusListWorkflow statusListWorkflow;

    @Override
    public Mono<CredentialStatus> allocateCredentialStatus(String issuerId, String procedureId, String token) {
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(procedureId, "procedureId cannot be null");

        return statusListWorkflow.allocateEntry(issuerId, StatusPurpose.REVOCATION, procedureId, token)
                .map(entry -> CredentialStatus.builder()
                        .id(entry.id())
                        .type(entry.type())
                        .statusPurpose(entry.statusPurpose().value())
                        .statusListIndex(String.valueOf(entry.statusListIndex()))
                        .statusListCredential(entry.statusListCredential())
                        .build());
    }
}

