package es.in2.issuer.backend.shared.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "issuer-identity")
@Validated
public record IssuerIdentityProperties(
        @NotBlank String credentialSubjectDidKey,
        @NotBlank String jwtCredential,
        @NotNull Crypto crypto
) {
    @ConstructorBinding
    public IssuerIdentityProperties(
            String credentialSubjectDidKey,
            String jwtCredential,
            Crypto crypto) {
        this.credentialSubjectDidKey = credentialSubjectDidKey;
        this.jwtCredential = jwtCredential;
        this.crypto = crypto;
    }

    @Validated
    public record Crypto(@NotBlank String privateKey) {
    }
}

