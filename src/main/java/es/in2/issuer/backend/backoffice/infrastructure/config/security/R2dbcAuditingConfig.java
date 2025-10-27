package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.ReactiveAuditorAware;
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@EnableR2dbcAuditing
public class R2dbcAuditingConfig {

    @Bean
    public ReactiveAuditorAware<String> auditorProvider() {
        return () -> ReactiveSecurityContextHolder.getContext()
                .doOnNext(ctx -> log.debug("Reactive auth: {}", ctx.getAuthentication()))
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.isAuthenticated() && auth.getName() != null)
                .map(Authentication::getName) // value of getName can be an email (from the mandatee of the access token) or 'system'
                .switchIfEmpty(Mono.just("system"));
    }
}

