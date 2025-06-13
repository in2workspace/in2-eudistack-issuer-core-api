package es.in2.issuer.backend.shared.domain.model.entities;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

// TODO: delete
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Table("issuer.deferred_credential_metadata")
public class DeferredCredentialMetadata {
    @Id
    @Column("id")
    private UUID id;

    @Column("transaction_code")
    private String transactionCode;

    @Column("auth_server_nonce")
    private String authServerNonce;

    @Column("transaction_id")
    private String transactionId;

    @Column("procedure_id")
    private UUID procedureId;

    @Column("vc")
    private String vc;

    @Column("vc_format")
    private String vcFormat;

    @Column("operation_mode")
    private String operationMode;

    @Column("response_uri")
    private String responseUri;
}
