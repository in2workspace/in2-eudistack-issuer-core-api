package es.in2.issuer.backend.backoffice.domain.repository;

import es.in2.issuer.backend.backoffice.domain.model.entities.StatusListCredentialMapping;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;

import java.util.UUID;

public interface StatusListCredentialMappingRepository extends ReactiveCrudRepository<StatusListCredentialMapping, UUID> {
}
