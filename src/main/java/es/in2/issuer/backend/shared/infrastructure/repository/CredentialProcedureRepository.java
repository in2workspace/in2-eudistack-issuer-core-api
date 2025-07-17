package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface CredentialProcedureRepository extends ReactiveCrudRepository<CredentialProcedure, UUID> {
    Flux<CredentialProcedure> findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum credentialStatusEnum, String organizationIdentifier);
    @Query("SELECT * FROM issuer.credential_procedure WHERE organization_identifier = :organizationIdentifier ORDER BY updated_at DESC")
    Flux<CredentialProcedure> findAllByOrganizationIdentifier(String organizationIdentifier);
    Mono<CredentialProcedure> findByProcedureIdAndOrganizationIdentifier(UUID procedureId, String organizationIdentifier);
    @Query("SELECT credential_status FROM issuer.credential_procedure WHERE procedure_id = :procedureId")
    Mono<String> findCredentialStatusByProcedureId(UUID procedureId);
    Mono<CredentialProcedure> findByCredentialId(UUID credentialId);
    Mono<CredentialProcedure> findByProcedureId(UUID procedureId);
}
