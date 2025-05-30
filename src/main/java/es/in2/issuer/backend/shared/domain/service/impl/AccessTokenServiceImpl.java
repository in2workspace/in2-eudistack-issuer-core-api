package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccessTokenServiceImpl implements AccessTokenService {

    private final ObjectMapper objectMapper;

    @Override
    public Mono<String> getCleanBearerToken(String authorizationHeader) {
        return Mono.just(authorizationHeader)
                .flatMap(header -> {
                    if (header.startsWith(BEARER_PREFIX)) {
                        return Mono.just(header.replace(BEARER_PREFIX, "").trim());
                    } else {
                        return Mono.just(header);
                    }
                });
    }

    @Override
    public Mono<String> getUserId(String authorizationHeader) {
        return getCleanBearerToken(authorizationHeader)
                .flatMap(token -> {
                    try {
                        SignedJWT parsedVcJwt = SignedJWT.parse(token);
                        JsonNode jsonObject = new ObjectMapper().readTree(parsedVcJwt.getPayload().toString());
                        return Mono.just(jsonObject.get("sub").asText());
                    } catch (ParseException | JsonProcessingException e) {
                        return Mono.error(e);
                    }
                })
                .switchIfEmpty(Mono.error(new InvalidTokenException()));
    }


    @Override
    public Mono<String> getOrganizationId(String authorizationHeader) {
        return getCleanBearerToken(authorizationHeader)
                .flatMap(this::extractOrganizationIdFromToken)
                .switchIfEmpty(Mono.error(new InvalidTokenException()));
    }

    @Override
    public Mono<String> getMandateeEmail(String authorizationHeader) {
        return getCleanBearerToken(authorizationHeader)
                .flatMap(this::extractMandateeEmailFromToken)
                .switchIfEmpty(Mono.error(new InvalidTokenException()));
    }


    private Mono<String> extractMandateeEmailFromToken(String token) {
        try {
            SignedJWT parsedVcJwt = SignedJWT.parse(token);
            JsonNode jsonObject = objectMapper.readTree(parsedVcJwt.getPayload().toString());
            String email = jsonObject.get(VC)
                    .get(CREDENTIAL_SUBJECT)
                    .get(MANDATE)
                    .get(MANDATEE)
                    .get(EMAIL)
                    .asText();
            return Mono.just(email);
        } catch (ParseException | JsonProcessingException e) {
            return Mono.error(new InvalidTokenException());
        }
    }

    @Override
    public Mono<String> getOrganizationIdFromCurrentSession() {
        return getTokenFromCurrentSession()
                .flatMap(this::getCleanBearerToken)
                .flatMap(this::extractOrganizationIdFromToken)
                .switchIfEmpty(Mono.error(new InvalidTokenException()));
    }

    private Mono<String> extractOrganizationIdFromToken(String token) {
        try {
            SignedJWT parsedVcJwt = SignedJWT.parse(token);
            JsonNode jsonObject = objectMapper.readTree(parsedVcJwt.getPayload().toString());
            String organizationId = jsonObject.get(VC)
                    .get(CREDENTIAL_SUBJECT)
                    .get(MANDATE)
                    .get(MANDATOR)
                    .get(ORGANIZATION_IDENTIFIER)
                    .asText();
            return Mono.just(organizationId);
        } catch (ParseException | JsonProcessingException e) {
            return Mono.error(new InvalidTokenException());
        }
    }

    private Mono<String> getTokenFromCurrentSession() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> {
                    JwtAuthenticationToken token = (JwtAuthenticationToken) ctx.getAuthentication();
                    return token.getToken().getTokenValue();
                });
    }
}
