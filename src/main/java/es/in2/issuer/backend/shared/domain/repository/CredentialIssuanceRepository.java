package es.in2.issuer.backend.shared.domain.repository;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialIssuanceRecord;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;

import java.util.UUID;

public interface CredentialIssuanceRepository extends ReactiveCrudRepository<CredentialIssuanceRecord, UUID> {
}