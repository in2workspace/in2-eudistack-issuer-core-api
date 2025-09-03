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
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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
        log.debug("🔐 CustomAuthenticationManager - authenticate - start");
        final String token = String.valueOf(authentication.getCredentials());

        return extractIssuer(token)
                .flatMap(issuer -> routeByIssuer(issuer, token))
                .onErrorMap(e -> (e instanceof AuthenticationException)
                        ? e
                        : new AuthenticationServiceException(e.getMessage(), e));
    }

    private Mono<String> extractIssuer(String token) {
        return Mono.fromCallable(() -> {
                    try {
                        return SignedJWT.parse(token);
                    } catch (ParseException e) {
                        log.error("❌ Failed to parse JWT", e);
                        throw new BadCredentialsException("Invalid JWT token format", e);
                    }
                })
                .flatMap(signedJWT -> {
                    try {
                        String issuer = signedJWT.getJWTClaimsSet().getIssuer();
                        log.debug("🔐 CustomAuthenticationManager - Issuer - {}", issuer);

                        if (issuer == null) {
                            log.error("❌ Missing issuer (iss) claim");
                            return Mono.error(new BadCredentialsException("Missing issuer (iss) claim"));
                        }
                        return Mono.just(issuer);

                    } catch (ParseException e) {
                       return Mono.error(e);
                    }
                })
                .onErrorMap(ParseException.class, e -> {
                    log.error("❌ Unable to parse JWT claims", e);
                    return new BadCredentialsException("Unable to parse JWT claims", e);
                });
    }


    private Mono<Authentication> routeByIssuer(String issuer, String token) {
        if (issuer.equals(appConfig.getVerifierUrl())) {
            log.debug("✅ Token from Verifier - {}", appConfig.getVerifierUrl());
            return handleVerifierToken(token);
        }
        if (issuer.equals(appConfig.getIssuerBackendUrl())) {
            log.debug("✅ Token from Credential Issuer - {}", appConfig.getIssuerBackendUrl());
            return handleIssuerBackendToken(token);
        }
        log.debug("❌ Token from unknown issuer");
        return Mono.error(new BadCredentialsException("Unknown token issuer: " + issuer));
    }

    private Mono<Authentication> handleVerifierToken(String token) {
        return verifierService.verifyToken(token)
                .then(parseAndValidateJwt(token, Boolean.TRUE))
                .map(jwt -> new JwtAuthenticationToken(jwt, Collections.emptyList()));
    }

    private Mono<Authentication> handleIssuerBackendToken(String token) {
        return Mono.fromCallable(() -> JWSObject.parse(token))
                .flatMap(jwtService::validateJwtSignatureReactive)
                .flatMap(isValid -> {
                    if (!Boolean.TRUE.equals(isValid)) {
                        log.error("❌ Invalid JWT signature");
                        return Mono.error(new BadCredentialsException("Invalid JWT signature"));
                    }
                    return parseAndValidateJwt(token, Boolean.FALSE)
                            .map(jwt -> (Authentication) new JwtAuthenticationToken(jwt, Collections.emptyList()));
                })
                .onErrorMap(ParseException.class, e -> {
                    log.error("❌ Failed to parse JWS", e);
                    return new BadCredentialsException("Invalid JWS token format", e);
                });
    }


    private Mono<Jwt> parseAndValidateJwt(String token, boolean validateVcClaim) {
        return Mono.fromCallable(() -> {
            log.debug("✅ parseAndValidateJwt");
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
            if(validateVcClaim)
                validateVcClaim(claims);

            // Extract issuedAt and expiresAt times if present
            Instant issuedAt = claims.containsKey("iat") ? Instant.ofEpochSecond(((Number) claims.get("iat")).longValue()) : Instant.now();
            Instant expiresAt = claims.containsKey("exp") ? Instant.ofEpochSecond(((Number) claims.get("exp")).longValue()) : Instant.now().plusSeconds(3600);

            return new Jwt(token, issuedAt, expiresAt, headers, claims);
        });
    }

    private void validateVcClaim(Map<String, Object> claims) {
        Object vcObj = claims.get("vc");
        log.debug("✅ validateVcClaim");
        if (vcObj == null) {
            log.error("❌ The 'vc' claim is required but not present.");
            throw new BadCredentialsException("The 'vc' claim is required but not present.");
        }
        String vcJson;
        if (vcObj instanceof String vc) {
            vcJson = vc;
        } else {
            try {
                vcJson = objectMapper.writeValueAsString(vcObj);
            } catch (Exception e) {
                log.error("❌ Error processing 'vc' claim.", e);
                throw new BadCredentialsException("Error processing 'vc' claim", e);
            }
        }
        JsonNode vcNode;
        try {
            vcNode = objectMapper.readTree(vcJson);
        } catch (Exception e) {
            log.error("❌ Error parsing 'vc' claim.", e);
            throw new BadCredentialsException("Error parsing 'vc' claim", e);
        }
        JsonNode typeNode = vcNode.get("type");
        if (typeNode == null || !typeNode.isArray() || StreamSupport.stream(typeNode.spliterator(), false)
                .noneMatch(node -> "LEARCredentialMachine".equals(node.asText()))) {
            log.error("❌Credential type required: LEARCredentialMachine.");
            throw new BadCredentialsException("Credential type required: LEARCredentialMachine.");
        }
    }
}