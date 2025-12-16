package es.in2.issuer.backend.backoffice.domain.model.entities;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name="signature_configuration_audit", schema = "identity_issuer")
public class SignatureConfigurationAudit {

    @Id
    @Column("id")
    private UUID id;

    @Column("signature_configuration_id")
    private String signatureConfigurationId;

    @Column("user_email")
    private String userEmail;

    @Column("organization_identifier")
    private String organizationIdentifier;

    @Column("instant")
    private Instant instant;

    @Column("old_values")
    private String oldValues;

    @Column("new_values")
    private String newValues;

    @Column("rationale")
    private String rationale;

    @Column("encrypted")
    private boolean encrypted;
}
