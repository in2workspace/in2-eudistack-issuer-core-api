package es.in2.issuer.backend.shared.infrastructure.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.ReactiveAuditorAware;
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@EnableR2dbcAuditing  // enable auditing support for R2DBC
public class R2dbcAuditingConfig {

    @Bean
    public ReactiveAuditorAware<String> auditorProvider() {
        return () -> ReactiveSecurityContextHolder.getContext()
                .doOnNext(ctx -> log.debug("Reactive auth: {}", ctx.getAuthentication()))
                .map(ctx -> ctx.getAuthentication())
                .filter(auth -> auth != null && auth.isAuthenticated() && auth.getName() != null)
                .map(Authentication::getName)
                .switchIfEmpty(Mono.just("system"));
    }
}

