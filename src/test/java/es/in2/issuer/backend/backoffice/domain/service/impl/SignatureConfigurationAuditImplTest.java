package es.in2.issuer.backend.backoffice.domain.service.impl;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.model.dtos.ChangeSet;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigAudit;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigurationResponse;
import es.in2.issuer.backend.backoffice.domain.model.entities.SignatureConfigurationAudit;
import es.in2.issuer.backend.backoffice.domain.repository.SignatureConfigurationAuditRepository;
import es.in2.issuer.backend.backoffice.domain.util.factory.SignatureConfigAuditFactory;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SignatureConfigurationAuditImplTest {

    @Mock SignatureConfigurationAuditRepository auditRepository;
    @Mock ObjectMapper objectMapper;
    @Mock SignatureConfigAuditFactory factory;
    @InjectMocks SignatureConfigurationAuditImpl service;

    private SignatureConfigurationResponse oldConfig;
    private ChangeSet changes;
    private final String rationale = "rationale";
    private final String userEmail = "user@example.com";

    @BeforeEach
    void setUp() {
        UUID id = UUID.randomUUID();
        oldConfig = SignatureConfigurationResponse.builder()
                .id(id)
                .organizationIdentifier("org-1")
                .enableRemoteSignature(true)
                .signatureMode(es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode.LOCAL)
                .cloudProviderId(id)
                .clientId("cid")
                .credentialId("crid")
                .credentialName("cname")
                .build();

        // Simulate that only clientId changed
        changes = new ChangeSet(
                Map.of("clientId", oldConfig.clientId()),
                Map.of("clientId", "cid-updated")
        );
    }

    @Test
    void saveAudit_success() throws JsonProcessingException {
        String oldJson = "{\"old\":true}";
        String newJson = "{\"new\":true}";

        // Stub JSON serialization of the two maps
        when(objectMapper.writeValueAsString(changes.oldValues())).thenReturn(oldJson);
        when(objectMapper.writeValueAsString(changes.newValues())).thenReturn(newJson);
        when(auditRepository.save(any(SignatureConfigurationAudit.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Mono<Void> result = service.saveAudit(oldConfig, changes, rationale, userEmail);

        StepVerifier.create(result)
                .verifyComplete();

        ArgumentCaptor<SignatureConfigurationAudit> captor =
                ArgumentCaptor.forClass(SignatureConfigurationAudit.class);
        verify(auditRepository).save(captor.capture());
        SignatureConfigurationAudit audit = captor.getValue();

        assertThat(audit.getSignatureConfigurationId())
                .isEqualTo(oldConfig.id().toString());
        assertThat(audit.getUserEmail()).isEqualTo(userEmail);
        assertThat(audit.getOrganizationIdentifier())
                .isEqualTo(oldConfig.organizationIdentifier());
        assertThat(audit.getOldValues()).isEqualTo(oldJson);
        assertThat(audit.getNewValues()).isEqualTo(newJson);
        assertThat(audit.getRationale()).isEqualTo(rationale);
        assertThat(audit.isEncrypted()).isFalse();
        assertThat(audit.getInstant()).isNotNull();
    }

    @Test
    void saveAudit_serializeOldValuesError() throws JsonProcessingException {
        when(objectMapper.writeValueAsString(changes.oldValues()))
                .thenThrow(new JsonProcessingException("fail") {});

        Mono<Void> result = service.saveAudit(oldConfig, changes, rationale, userEmail);

        StepVerifier.create(result)
                .expectErrorMatches(e ->
                        e instanceof ParseErrorException &&
                                e.getMessage().contains("Error serializing audit change set")
                )
                .verify();
    }

    @Test
    void saveDeletionAudit_success() throws JsonProcessingException {
        String oldJson = "{\"old\":true}";

        when(objectMapper.writeValueAsString(oldConfig)).thenReturn(oldJson);
        when(auditRepository.save(any(SignatureConfigurationAudit.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        Mono<Void> result = service.saveDeletionAudit(oldConfig, rationale, userEmail);

        StepVerifier.create(result)
                .verifyComplete();

        ArgumentCaptor<SignatureConfigurationAudit> captor =
                ArgumentCaptor.forClass(SignatureConfigurationAudit.class);
        verify(auditRepository).save(captor.capture());
        SignatureConfigurationAudit audit = captor.getValue();

        assertThat(audit.getSignatureConfigurationId()).isEqualTo(oldConfig.id().toString());
        assertThat(audit.getOldValues()).isEqualTo(oldJson);
        assertThat(audit.getNewValues()).isNull();
        assertThat(audit.getRationale()).isEqualTo(rationale);
        assertThat(audit.isEncrypted()).isFalse();
        assertThat(audit.getInstant()).isNotNull();
    }

    @Test
    void saveDeletionAudit_serializeError() throws JsonProcessingException {
        when(objectMapper.writeValueAsString(oldConfig))
                .thenThrow(new JsonProcessingException("err") {});

        Mono<Void> result = service.saveDeletionAudit(oldConfig, rationale, userEmail);

        StepVerifier.create(result)
                .expectErrorMatches(e ->
                        e instanceof ParseErrorException &&
                                e.getMessage().contains(
                                        "Error serializing old config for deletion audit with ID: " + oldConfig.id()
                                )
                )
                .verify();
    }

    @Test
    void getAllAudits_mapsEntities() {
        SignatureConfigurationAudit entity = SignatureConfigurationAudit.builder()
                .id(UUID.randomUUID())
                .signatureConfigurationId("id1")
                .userEmail("u1")
                .organizationIdentifier("org-1")
                .instant(Instant.now())
                .oldValues("{}")
                .newValues("{}")
                .rationale("r")
                .encrypted(false)
                .build();
        SignatureConfigAudit dto = mock(SignatureConfigAudit.class);

        when(auditRepository.findAll()).thenReturn(Flux.just(entity));
        when(factory.createFromEntity(entity)).thenReturn(dto);

        StepVerifier.create(service.getAllAudits())
                .expectNext(dto)
                .verifyComplete();
    }

    @Test
    void getAuditsByOrganization_mapsEntities() {
        String org = "org-XYZ";
        SignatureConfigurationAudit entity = SignatureConfigurationAudit.builder()
                .id(UUID.randomUUID())
                .signatureConfigurationId("id2")
                .userEmail("u2")
                .organizationIdentifier(org)
                .instant(Instant.now())
                .oldValues("{}")
                .newValues("{}")
                .rationale("r2")
                .encrypted(true)
                .build();
        SignatureConfigAudit dto = mock(SignatureConfigAudit.class);

        when(auditRepository.findAllByOrganizationIdentifier(org))
                .thenReturn(Flux.just(entity));
        when(factory.createFromEntity(entity)).thenReturn(dto);

        StepVerifier.create(service.getAuditsByOrganization(org))
                .expectNext(dto)
                .verifyComplete();
    }
}