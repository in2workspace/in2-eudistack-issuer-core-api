package es.in2.issuer.backend.backoffice.infrastructure.config;

import es.in2.issuer.backend.backoffice.infrastructure.config.properties.HashicorpVaultProperties;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractReactiveVaultConfiguration;

import java.util.Base64;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class HashicorpVaultConfig extends AbstractReactiveVaultConfiguration {
    private final HashicorpVaultProperties properties;

    @Override
    @NonNull
    public VaultEndpoint vaultEndpoint() {
        return VaultEndpoint.from(properties.url());
    }

    @Override
    @NonNull
    public ClientAuthentication clientAuthentication() {
        String decodedToken = this.decodeIfBase64(properties.token());
        return new TokenAuthentication(decodedToken);
    }

    private String decodeIfBase64(String token) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(token);
            return new String(decodedBytes).trim();
        } catch (IllegalArgumentException ex) {
            return token.trim();
        }
    }
}
