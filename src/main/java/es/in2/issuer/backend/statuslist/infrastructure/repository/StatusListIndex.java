package es.in2.issuer.backend.statuslist.infrastructure.repository;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("status_list_index")
public record StatusListIndex(
        @Id
        Long id,

        @Column("status_list_id")
        Long statusListId,

        @Column("idx")
        Integer idx,

        @Column("procedure_id")
        UUID procedureId,

        @Column("created_at")
        Instant createdAt
) { }


