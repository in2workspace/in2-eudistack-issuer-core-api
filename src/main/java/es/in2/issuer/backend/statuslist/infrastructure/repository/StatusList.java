package es.in2.issuer.backend.statuslist.infrastructure.repository;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("status_list")
public record StatusList(
        @Id Long id,
        @Column("purpose") String purpose,
        @Column("encoded_list") String encodedList,
        @Column("signed_credential") String signedCredential,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt
) { }

