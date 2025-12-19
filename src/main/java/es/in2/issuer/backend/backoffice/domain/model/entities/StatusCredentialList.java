package es.in2.issuer.backend.backoffice.domain.model.entities;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.OffsetDateTime;
import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table("issuer.status_list_index")
public class StatusCredentialList {

    //revisar tipus
    @Id
    @Column("id")
    private UUID id;

    @Column("list_id")
    private int listId;

    @Column("status_purpose")
    private String statusPurpose;

    @Column("size_bits")
    private Integer sizeBits;

    @Column("bitstring")
    private byte[] bitstring;

    //aquí? serà sempre el did del tenant
    @Column("issuer")
    private String issuer;

    @Column("valid_from")
    private OffsetDateTime validFrom;

    @Column("valid_until")
    private OffsetDateTime validUntil;

    @Column("created_at")
    private OffsetDateTime createdAt;

    @Column("updated_at")
    private OffsetDateTime updatedAt;

    @Column("created_by")
    private String createdBy;

    @Column("updated_by")
    private String updatedBy;
}
