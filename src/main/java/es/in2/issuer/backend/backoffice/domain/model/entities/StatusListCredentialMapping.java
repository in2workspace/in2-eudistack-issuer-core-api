package es.in2.issuer.backend.backoffice.domain.model.entities;

import lombok.*;
import org.springframework.data.annotation.*;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.OffsetDateTime;
import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table("issuer.credential_status_mapping")
public class StatusListCredentialMapping {

    //todo revisar tipus
    @Id
    @Column("id")
    private UUID id;

    @Column("credential_id")
    private String credentialId;

    @Column("status_list_id")
    private UUID statusListId;

    @Column("status_list_index")
    private Long statusListIndex; //long?

    @Column("bit_status")
    private Boolean bitStatus; // TRUE = revoked; cal?

    @Column("status_purpose")
    private String statusPurpose;

    //cal? cal audit?
    @CreatedDate
    @Column("created_at")
    private OffsetDateTime createdAt;

    @LastModifiedDate
    @Column("updated_at")
    private OffsetDateTime updatedAt;

    @CreatedBy
    @Column("created_by")
    private String createdBy;

    @LastModifiedBy
    @Column("updated_by")
    private String updatedBy;
}
