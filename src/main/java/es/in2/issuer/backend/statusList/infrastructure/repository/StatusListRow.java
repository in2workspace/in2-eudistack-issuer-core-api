package es.in2.issuer.backend.statusList.infrastructure.repository;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("status_list")
public record StatusListRow(
        @Id Long id,
        @Column("issuer_id") String issuerId,
        @Column("purpose") String purpose,
        @Column("encoded_list") String encodedList,
        @Column("signed_credential") String signedCredential,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt
) { }

