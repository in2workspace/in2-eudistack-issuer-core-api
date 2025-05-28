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
@Table("issuer.configuration")
public class Configuration {

    @Id
    @Column("id")
    private UUID id;

    @Column("organization_identifier")
    private String organizationIdentifier;

    @Column("config_key")
    private String configKey;

    @Column("config_value")
    private String configvalue;

}
