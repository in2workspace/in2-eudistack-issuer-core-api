package es.in2.issuer.backend.backoffice.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigAudit;
import es.in2.issuer.backend.backoffice.domain.model.entities.SignatureConfigurationAudit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SignatureConfigAuditFactoryTest {

    @InjectMocks
    private SignatureConfigAuditFactory factory;
    @Mock
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        factory = new SignatureConfigAuditFactory(objectMapper);
    }

    @Test
    void createFromEntity_allValidJson() {
        UUID id = UUID.randomUUID();
        String oldJson = "{\"a\":1}";
        String newJson = "{\"b\":\"value\"}";
        SignatureConfigurationAudit entity = SignatureConfigurationAudit.builder()
                .id(id)
                .signatureConfigurationId("sig-123")
                .userEmail("user@example.com")
                .organizationIdentifier("org-1")
                .instant(Instant.parse("2025-05-10T12:34:56Z"))
                .oldValues(oldJson)
                .newValues(newJson)
                .rationale("because")
                .encrypted(true)
                .build();

        SignatureConfigAudit dto = factory.createFromEntity(entity);

        assertThat(dto.id()).isEqualTo(id.toString());
        assertThat(dto.signatureConfigurationId()).isEqualTo("sig-123");
        assertThat(dto.userEmail()).isEqualTo("user@example.com");
        assertThat(dto.organizationIdentifier()).isEqualTo("org-1");
        assertThat(dto.instant()).isEqualTo("2025-05-10T12:34:56Z");
        assertThat(dto.rationale()).isEqualTo("because");
        assertThat(dto.encrypted()).isTrue();

        JsonNode oldNode = dto.oldValues();
        JsonNode newNode = dto.newValues();
        assertThat(oldNode.get("a").asInt()).isEqualTo(1);
        assertThat(newNode.get("b").asText()).isEqualTo("value");
    }

    @Test
    void createFromEntity_nullJsons() {
        SignatureConfigurationAudit entity = SignatureConfigurationAudit.builder()
                .id(UUID.randomUUID())
                .signatureConfigurationId("sig-456")
                .userEmail("u@e.com")
                .organizationIdentifier("org-2")
                .instant(Instant.parse("2025-01-01T00:00:00Z"))
                .oldValues(null)
                .newValues(null)
                .rationale(null)
                .encrypted(false)
                .build();

        SignatureConfigAudit dto = factory.createFromEntity(entity);

        assertThat(dto.oldValues().isObject()).isTrue();
        assertThat(dto.oldValues()).isEmpty();
        assertThat(dto.newValues()).isNull();
    }

    @Test
    void createFromEntity_invalidOldJson_validNewJson() {
        String badOld = "{invalid...";
        String goodNew = "{\"x\":42}";
        SignatureConfigurationAudit entity = SignatureConfigurationAudit.builder()
                .id(UUID.randomUUID())
                .signatureConfigurationId("sig-789")
                .userEmail("foo@bar.com")
                .organizationIdentifier("org-3")
                .instant(Instant.now())
                .oldValues(badOld)
                .newValues(goodNew)
                .rationale("r")
                .encrypted(false)
                .build();

        SignatureConfigAudit dto = factory.createFromEntity(entity);

        // old falls back to empty object
        assertThat(dto.oldValues().isObject()).isTrue();
        assertThat(dto.oldValues()).isEmpty();
        // new parsed correctly
        assertThat(dto.newValues().get("x").asInt()).isEqualTo(42);
    }

    @Test
    void createFromEntity_validOldJson_invalidNewJson() {
        String goodOld = "{\"foo\":\"bar\"}";
        String badNew = "[not json";
        SignatureConfigurationAudit entity = SignatureConfigurationAudit.builder()
                .id(UUID.randomUUID())
                .signatureConfigurationId("sig-000")
                .userEmail("e@e.com")
                .organizationIdentifier("org-4")
                .instant(Instant.parse("2025-12-31T23:59:59Z"))
                .oldValues(goodOld)
                .newValues(badNew)
                .rationale("test")
                .encrypted(true)
                .build();

        SignatureConfigAudit dto = factory.createFromEntity(entity);

        // old parsed correctly
        assertThat(dto.oldValues().get("foo").asText()).isEqualTo("bar");
        // new falls back to null
        assertThat(dto.newValues()).isNull();
    }
}
