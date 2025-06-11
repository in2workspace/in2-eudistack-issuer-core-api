package es.in2.issuer.backend.shared.domain.model.entities;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatus;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.sql.Timestamp;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@Table("issuer.credential_issuance_record")
public class CredentialIssuanceRecord {
    @Id
    @Column("id")
    private UUID id;

    @Column("organization_identifier")
    private String organizationIdentifier;

    @Column("subject")
    private String subject;

    @Column("email")
    private String email;

    // jwt_vc_json
    @Column("credential_format")
    private String credentialFormat;

    // LEARCredentialEmployee, LEARCredentialMachine, VerifiableCertification...
    @Column("credential_type")
    private String credentialType;

    @Column("credential_status")
    private CredentialStatus credentialStatus;

    @Column("credential_data")
    private String credentialData;

    // Issuance Metadata

    @Column("preauthorized_code")
    private String preAuthorizedCode;

    @Column("access_token_jti")
    private String accessTokenJti;

    @Column("refresh_token_jti")
    private String refreshTokenJti;

    @Column("transaction_id")
    private String transactionId;

    // S or A (non-supported yet)
    @Column("operation_mode")
    private String operationMode;

    @Column("signature_mode")
    private String signatureMode;

    @Column("created_at")
    private Timestamp createdAt;

    @Column("updated_at")
    private Timestamp updatedAt;
}
