package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
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
import java.text.ParseException;
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
    private final AppConfig appConfig;
    private final JWTService jwtService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        log.debug("🔐 CustomAuthenticationManager - received token: {}", authentication.getCredentials());
        String token = authentication.getCredentials().toString();

        return Mono.fromCallable(() -> {
                    try {
                        return SignedJWT.parse(token);
                    } catch (ParseException e) {
                            log.error("❌ Failed to parse JWT", e);
                            throw new BadCredentialsException("Invalid JWT token format", e);
                    }
                })
                .flatMap(signedJWT -> {
                    String issuer;
                    try {
                        issuer = signedJWT.getJWTClaimsSet().getIssuer();
                    } catch (ParseException e) {
                        log.error("❌ Unable to parse JWT claims", e);
                        return Mono.error(new BadCredentialsException("Unable to parse JWT claims", e));
                    }

                    if (issuer == null) {
                        return Mono.error(new BadCredentialsException("Missing issuer (iss) claim"));
                    }

                    if (issuer.equals(appConfig.getVerifierUrl())) {
                        // Caso Verifier → validar vía microservicio Verifier
                        log.debug("✅ Token from Verifier");
                        return verifierService.verifyToken(token)
                                .then(parseAndValidateJwt(token))
                                .map(jwt -> new JwtAuthenticationToken(jwt, Collections.emptyList()));
                    } else if (issuer.equals(appConfig.getIssuerBackendUrl())) {
                        // Caso Credential Issuer (Keycloak) → validar firma local
                        log.debug("✅ Token from Credential Issuer");
                        return Mono.fromCallable(() -> JWSObject.parse(token))
                                .flatMap(jwsObject -> jwtService.validateJwtSignatureReactive(jwsObject)
                                        .flatMap(isValid -> {
                                            if (!isValid) {
                                                return Mono.error(new BadCredentialsException("Invalid JWT signature"));
                                            }
                                            return parseAndValidateJwt(token)
                                                    .map(jwt -> (Authentication) new JwtAuthenticationToken(jwt, Collections.emptyList()));
                                        }));
                    } else {
                        log.debug("✅ Token from unknow");
                        return Mono.error(new BadCredentialsException("Unknown token issuer: " + issuer));
                    }
                });
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