package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
public final class DualTokenServerAuthenticationConverter implements ServerAuthenticationConverter {

    private static final String ID_TOKEN_HEADER = "X-ID-Token";

    @Override
    public Mono<org.springframework.security.core.Authentication> convert(ServerWebExchange exchange) {
        var request = exchange.getRequest();
        var path = request.getPath();
        var method = request.getMethod();
        log.debug("CustomAuthenticationWebFilter triggered -> [{} {}]",
                method,
                path);

        String auth = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth == null || !auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Mono.empty();
        }
        String accessToken = auth.substring(7).trim();
        String idToken = request.getHeaders().getFirst(ID_TOKEN_HEADER);
        return Mono.just(new DualTokenAuthentication(accessToken, (idToken == null || idToken.isBlank()) ? null : idToken));
    }
}

