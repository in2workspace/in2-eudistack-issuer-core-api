package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.backoffice.domain.model.dtos.ChangeSet;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigAudit;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigurationResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface SignatureConfigurationAuditService {
    Mono<Void> saveAudit( SignatureConfigurationResponse oldConfig, ChangeSet changes, String rationale, String userEmail);
    Mono<Void> saveDeletionAudit(SignatureConfigurationResponse oldConfig, String rationale, String userEmail);

    Flux<SignatureConfigAudit> getAllAudits();
    Flux<SignatureConfigAudit> getAuditsByOrganization(String organizationIdentifier);
}
