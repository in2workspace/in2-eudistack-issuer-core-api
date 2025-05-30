package es.in2.issuer.backend.backoffice.domain.repository;

import es.in2.issuer.backend.backoffice.domain.model.entities.CloudProvider;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface CloudProviderRepository extends ReactiveCrudRepository<CloudProvider, UUID> {

}
