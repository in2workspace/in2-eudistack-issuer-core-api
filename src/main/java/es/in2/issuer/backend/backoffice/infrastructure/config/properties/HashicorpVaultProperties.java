package es.in2.issuer.backend.backoffice.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "vault.hashicorp")
@Validated
public record HashicorpVaultProperties(
        @URL String url,
        @NotBlank String token,
        @NotBlank String secretsMount) {
}
