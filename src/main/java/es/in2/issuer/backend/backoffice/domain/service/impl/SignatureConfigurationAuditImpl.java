package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.model.dtos.ChangeSet;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigAudit;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigurationResponse;
import es.in2.issuer.backend.backoffice.domain.model.entities.SignatureConfigurationAudit;
import es.in2.issuer.backend.backoffice.domain.repository.SignatureConfigurationAuditRepository;
import es.in2.issuer.backend.backoffice.domain.service.SignatureConfigurationAuditService;
import es.in2.issuer.backend.backoffice.domain.util.factory.SignatureConfigAuditFactory;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class SignatureConfigurationAuditImpl implements SignatureConfigurationAuditService {
    private final SignatureConfigurationAuditRepository auditRepository;
    private final ObjectMapper objectMapper;
    private final SignatureConfigAuditFactory factory;


    @Override
    public Mono<Void> saveAudit(SignatureConfigurationResponse oldConfig, ChangeSet changes, String rationale, String userEmail) {

        try {
            // Serialize only the changed fields
            String oldJson = objectMapper.writeValueAsString(changes.oldValues());
            String newJson = objectMapper.writeValueAsString(changes.newValues());

            SignatureConfigurationAudit audit = SignatureConfigurationAudit.builder()
                    .signatureConfigurationId(oldConfig.id().toString())
                    .userEmail(userEmail)
                    .organizationIdentifier(oldConfig.organizationIdentifier())
                    .instant(Instant.now())
                    .oldValues(oldJson)
                    .newValues(newJson)
                    .rationale(rationale)
                    .encrypted(false)
                    .build();

            return auditRepository.save(audit).then();

        } catch (JsonProcessingException e) {
            return Mono.error(new ParseErrorException(
                    "Error serializing audit change set: " + e.getMessage()));
        }
    }

    @Override
    public Mono<Void> saveDeletionAudit(SignatureConfigurationResponse oldConfig, String rationale, String userEmail) {
        try {
            String oldJson = objectMapper.writeValueAsString(oldConfig);

            SignatureConfigurationAudit audit = SignatureConfigurationAudit.builder()
                    .signatureConfigurationId(oldConfig.id().toString())
                    .userEmail(userEmail)
                    .organizationIdentifier(oldConfig.organizationIdentifier())
                    .instant(Instant.now())
                    .oldValues(oldJson)
                    .rationale(rationale)
                    .encrypted(false)
                    .build();

            return auditRepository.save(audit).then();
        } catch (JsonProcessingException e) {
            return Mono.error(new ParseErrorException("Error serializing old config for deletion audit with ID: " + oldConfig.id()));
        }
    }

    @Override
    public Flux<SignatureConfigAudit> getAllAudits() {
        return auditRepository.findAll()
                .map(factory:: createFromEntity);
    }

    @Override
    public Flux<SignatureConfigAudit> getAuditsByOrganization(String organizationIdentifier) {
        return auditRepository.findAllByOrganizationIdentifier(organizationIdentifier)
                .map(factory::createFromEntity);
    }

}