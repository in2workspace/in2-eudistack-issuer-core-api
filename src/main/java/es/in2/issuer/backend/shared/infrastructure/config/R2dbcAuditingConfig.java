package es.in2.issuer.backend.shared.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.ReactiveAuditorAware;
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import reactor.core.publisher.Mono;

@Configuration
@EnableR2dbcAuditing  // enable auditing support for R2DBC
public class R2dbcAuditingConfig {

    @Bean
    public ReactiveAuditorAware<String> auditorProvider() {
        return () -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && auth.getName() != null) {
                return Mono.just(auth.getName());
            }
            return Mono.just("system");
        };
    }
}

