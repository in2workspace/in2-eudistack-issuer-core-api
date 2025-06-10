package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedDataCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialIssuanceRecord;
import reactor.core.publisher.Mono;

public interface CredentialIssuanceRecordService {
    Mono<String> create(
            String processId,
            PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest,
            String token);

    Mono<CredentialIssuanceRecord> get(String id);

    Mono<Void> setPreAuthorizedCodeById(String id, String preAuthorizedCode);
}
