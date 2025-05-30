package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.GetAuthorizationServerMetadataWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationServerMetadata;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.ENGLISH;

@Slf4j
@RestController
@RequestMapping("/.well-known/openid-configuration")
@RequiredArgsConstructor
public class AuthorizationServerMetadataController {

    private final GetAuthorizationServerMetadataWorkflow getAuthorizationServerMetadataWorkflow;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<AuthorizationServerMetadata> getCredentialIssuerMetadata(ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().add(HttpHeaders.CONTENT_LANGUAGE, ENGLISH);
        return getAuthorizationServerMetadataWorkflow.execute(processId)
                .doFirst(() ->
                        log.info("Process ID: {} - Getting Authorization Server Metadata...", processId))
                .doOnSuccess(credentialOffer ->
                        log.info("Process ID: {} - Authorization Server Metadata generated successfully.", processId));
    }

}
