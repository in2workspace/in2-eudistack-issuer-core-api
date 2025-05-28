package es.in2.issuer.backend.backoffice.domain.model.dtos;

import lombok.Builder;

@Builder
public record SignatureVaultSecret(

        String clientSecret,
        String credentialPassword,
        String secret
) { }