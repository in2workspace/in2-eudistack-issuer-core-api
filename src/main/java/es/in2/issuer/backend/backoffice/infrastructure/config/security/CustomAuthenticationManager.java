package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.infrastructure.config.security.exception.ParseAuthenticationException;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.stream.StreamSupport;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationManager implements ReactiveAuthenticationManager {

    private final VerifierService verifierService;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        log.info("authenticate");
        String token = authentication.getCredentials().toString();

        return verifierService.verifyToken(token)
                .then(parseAndValidateJwt(token))
                .map(jwt -> (Authentication) new JwtAuthenticationToken(jwt, Collections.emptyList()))
                .doOnError(e -> log.error("Error authenticating token from authenticate", e));
    }

    private Mono<Jwt> parseAndValidateJwt(String token) {
        return Mono.fromCallable(() -> {
            String[] parts = token.split("\\.");
            if (parts.length < 3) {
                throw new BadCredentialsException("Invalid JWT token format");
            }

            // Decode and parse headers
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            Map<String, Object> headers = objectMapper.readValue(headerJson, Map.class);

            // Decode and parse payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            Map<String, Object> claims = objectMapper.readValue(payloadJson, Map.class);

            // Validate 'vc' claim
            validateVcClaim(claims);

            // Extract issuedAt and expiresAt times if present
            Instant issuedAt = claims.containsKey("iat") ? Instant.ofEpochSecond(((Number) claims.get("iat")).longValue()) : Instant.now();
            Instant expiresAt = claims.containsKey("exp") ? Instant.ofEpochSecond(((Number) claims.get("exp")).longValue()) : Instant.now().plusSeconds(3600);

            return new Jwt(token, issuedAt, expiresAt, headers, claims);
        });
    }

    private void validateVcClaim(Map<String, Object> claims) {
        Object vcObj = claims.get("vc");
        if (vcObj == null) {
            throw new BadCredentialsException("The 'vc' claim is required but not present.");
        }
        String vcJson;
        if (vcObj instanceof String vc) {
            vcJson = vc;
        } else {
            try {
                vcJson = objectMapper.writeValueAsString(vcObj);
            } catch (Exception e) {
                throw new BadCredentialsException("Error processing 'vc' claim", e);
            }
        }
        JsonNode vcNode;
        try {
            vcNode = objectMapper.readTree(vcJson);
        } catch (Exception e) {
            throw new BadCredentialsException("Error parsing 'vc' claim", e);
        }
        JsonNode typeNode = vcNode.get("type");
        if (typeNode == null || !typeNode.isArray() || StreamSupport.stream(typeNode.spliterator(), false).noneMatch(node -> "LEARCredentialMachine".equals(node.asText()))) {
            throw new BadCredentialsException("Credential type required: LEARCredentialMachine.");
        }
    }
}