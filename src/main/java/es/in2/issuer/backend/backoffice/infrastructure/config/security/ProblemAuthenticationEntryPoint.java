package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Slf4j
@RequiredArgsConstructor
@Component
public class ProblemAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final ErrorResponseFactory errors;
    private final SecurityProblemResolver resolver;

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        log.debug("ProblemAuthenticationEntryPoint.commence - inside");
        log.debug("Exception: ", ex);

        var response = exchange.getResponse();
        var spec = resolver.resolve(ex, true);

        response.setStatusCode(spec.status());
        response.getHeaders().setContentType(MediaType.valueOf("application/problem+json"));

        var msg = errors.handleWithNow(
                ex,
                exchange.getRequest(),
                spec.type(),
                spec.title(),
                spec.status(),
                spec.fallbackDetail()
        );

        try {
            byte[] body = objectMapper.writeValueAsBytes(msg);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
        } catch (Exception e) {
            byte[] fallback = "{\"title\":\"Unauthorized\",\"status\":401}"
                    .getBytes(StandardCharsets.UTF_8);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(fallback)));
        }
    }
}
