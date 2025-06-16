package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedDataCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialIssuanceRecord;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatus;
import reactor.core.publisher.Mono;

public interface CredentialIssuanceRecordService {
    Mono<String> create(
            String processId,
            PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest,
            String token);

    Mono<CredentialIssuanceRecord> get(String id);

    Mono<Void> setPreAuthorizedCodeById(CredentialIssuanceRecord credentialIssuanceRecord, String preAuthorizedCode);

    Mono<String> getIdByPreAuthorizedCode(String preAuthorizedCode);

    Mono<Void> setJtis(String id, String accessToken, String refreshToken);

    Mono<CredentialIssuanceRecord> getByJti(String accessTokenJti);

    Mono<Void> updateOperationModeAndStatus(String id, String operationMode, CredentialStatus credentialStatus);

    Mono<Void> setTransactionCodeById(String id, String transactionId);

    Mono<Void> update(CredentialIssuanceRecord credentialIssuanceRecord);

    Mono<String> getOperationModeById(String id);
}
