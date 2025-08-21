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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Component
public class ProblemAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final ErrorResponseFactory errors;

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        log.info("ProblemAuthenticationEntryPoint.commence");
        log.info("Exception: ", ex);
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.valueOf("application/problem+json"));

        var problem = Map.of(
                "type", "authentication_error_custom",
                "title", "Unauthorized custom",
                "status", HttpStatus.UNAUTHORIZED.value(),
                "detail", ex.getMessage() != null ? ex.getMessage() : "Authentication failed custom",
                "instance", UUID.randomUUID().toString()
        );

        try {
            byte[] body = objectMapper.writeValueAsBytes(problem);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
        } catch (Exception e) {
            byte[] fallback = "{\"title\":\"Unauthorized\",\"status\":401}"
                    .getBytes(StandardCharsets.UTF_8);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(fallback)));
        }
    }
}
