package es.in2.issuer.backend.shared.domain.repository;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialIssuanceRecord;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface CredentialIssuanceRepository extends ReactiveCrudRepository<CredentialIssuanceRecord, UUID> {

    Mono<CredentialIssuanceRecord> findByPreAuthorizedCode(String preAuthorizedCode);

    Mono<CredentialIssuanceRecord> findByAccessTokenJti(String accessTokenJti);
}