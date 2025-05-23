package es.in2.issuer.backend.shared.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "default-signer")
@Validated
public record DefaultSignerProperties(
        @NotBlank String commonName,
        @NotBlank String country,
        @NotBlank String email,
        @NotBlank String organizationIdentifier,
        @NotBlank String organization,
        @NotBlank String serialNumber

) {}
