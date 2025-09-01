package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import es.in2.issuer.backend.shared.infrastructure.config.AuthServerConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

@Slf4j
@Configuration
public class JwtDecoderConfig {

    private final AuthServerConfig authServerConfig;

    public JwtDecoderConfig(AuthServerConfig authServerConfig) {
        this.authServerConfig = authServerConfig;
    }

    @Bean
    public ReactiveJwtDecoder internalJwtDecoder() {
//        todo remove
        log.info("ReactiveJwtDecoder");
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder
                .withJwkSetUri(authServerConfig.getJwtDecoder())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(authServerConfig.getJwtValidator()));
        return jwtDecoder;
    }
}
