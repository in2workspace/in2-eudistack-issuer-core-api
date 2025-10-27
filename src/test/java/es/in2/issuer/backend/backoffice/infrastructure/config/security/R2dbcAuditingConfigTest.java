package es.in2.issuer.backend.backoffice.infrastructure.config.security;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.ReactiveAuditorAware;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.*;

class R2dbcAuditingConfigTest {

    private ReactiveAuditorAware<String> auditorAware;

    @BeforeEach
    void setUp() {
        // Instantiate the config and obtain the bean under test
        R2dbcAuditingConfig config = new R2dbcAuditingConfig();
        this.auditorAware = config.auditorProvider();
    }

    @Test
    void whenAuthenticatedUser_thenEmitsUsername() {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                "alice@example.com",
                "pw",
                java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"))
        );

        Mono<String> result = auditorAware.getCurrentAuditor()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));

        StepVerifier.create(result)
                .expectNext("alice@example.com")
                .verifyComplete();
    }


    @Test
    void whenUnauthenticatedUser_thenEmitsSystem() {
        // Given an unauthenticated Authentication in the context
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(false);
        when(auth.getName()).thenReturn("ignored");

        Mono<String> result = auditorAware.getCurrentAuditor()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));

        StepVerifier.create(result)
                .expectNext("system")
                .verifyComplete();
    }

    @Test
    void whenAuthenticatedButNameIsNull_thenEmitsSystem() {
        // Given an authenticated Authentication whose getName() returns null
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getName()).thenReturn(null);

        Mono<String> result = auditorAware.getCurrentAuditor()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));

        StepVerifier.create(result)
                .expectNext("system")
                .verifyComplete();
    }

    @Test
    void whenNoSecurityContext_thenEmitsSystem() {
        // Given no ReactiveSecurityContext at all
        Mono<String> result = auditorAware.getCurrentAuditor();

        StepVerifier.create(result)
                .expectNext("system")
                .verifyComplete();
    }
}
