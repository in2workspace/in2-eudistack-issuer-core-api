package es.in2.issuer.backend.backoffice.domain.model.entities;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Table("issuer.cloud_provider")
public class CloudProvider {

    @Id
    @Column("id")
    private UUID id;

    @Column("provider")
    private String provider;

    @Column("url")
    private String url;

    @Column("auth_method")
    private String authMethod;

    @Column("auth_grant_type")
    private String authGrantType;

    @Column("requires_totp")
    private boolean requiresTOTP;
}
