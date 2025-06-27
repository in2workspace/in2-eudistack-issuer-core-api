package es.in2.issuer.backend.backoffice.domain.model.entities;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table("issuer.status_list_index")
public class StatusListIndex {

    @Id
    @Column("nonce")
    private UUID nonce;

    @Column("list_id")
    private int listId;
}
