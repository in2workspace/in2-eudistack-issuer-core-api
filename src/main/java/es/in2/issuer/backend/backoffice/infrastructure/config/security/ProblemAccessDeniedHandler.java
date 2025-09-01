package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class ProblemAccessDeniedHandler implements ServerAccessDeniedHandler {

    private final ObjectMapper objectMapper;
    private final ErrorResponseFactory errors;
    private final SecurityProblemResolver resolver;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException ex) {

        var response = exchange.getResponse();
        var spec = resolver.resolve(ex, false);

        response.setStatusCode(spec.status());
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);

        var body = errors.handleWithNow(
                ex,
                exchange.getRequest(),
                spec.type(),
                spec.title(),
                spec.status(),
                spec.fallbackDetail()
        );

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
        } catch (Exception ser) {
            byte[] fallback = "{\"title\":\"Forbidden\",\"status\":403}".getBytes(StandardCharsets.UTF_8);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(fallback)));
        }
    }
}


