package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import es.in2.issuer.backend.shared.infrastructure.config.AuthServerConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

@Configuration
public class JwtDecoderConfig {

    private final AuthServerConfig authServerConfig;

    public JwtDecoderConfig(AuthServerConfig authServerConfig) {
        this.authServerConfig = authServerConfig;
    }

    @Bean
    public ReactiveJwtDecoder internalJwtDecoder() {
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder
                .withJwkSetUri(authServerConfig.getJwtDecoder())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(authServerConfig.getJwtValidator()));
        return jwtDecoder;
    }
}
