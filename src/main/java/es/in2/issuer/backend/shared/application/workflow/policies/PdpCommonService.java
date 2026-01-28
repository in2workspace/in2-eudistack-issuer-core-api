package es.in2.issuer.backend.shared.application.workflow.policies;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.ROLE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.VC;

@Slf4j
@Service
@RequiredArgsConstructor
public class PdpCommonService {

    private static final String ROLE_CLAIM = ROLE;
    private static final String VC_CLAIM = VC;

    private final AppConfig appConfig;
    private final JWTService jwtService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    public Mono<SignedJWT> parseAndValidateRole(String token, String requiredRole) {
        return parseToken(token)
                .flatMap(jwt ->
                        extractRole(jwt)
                                .flatMap(role -> ensureRoleIs(role, requiredRole))
                                .thenReturn(jwt)
                );
    }

    public Mono<String> extractUserOrganizationIdentifier(SignedJWT signedJWT) {
        Payload payload = signedJWT.getPayload();
        String vcClaim = jwtService.getClaimFromPayload(payload, VC_CLAIM);

        // TODO: Adapt to all credential types if needed
        String userOrganizationIdentifier =
                learCredentialEmployeeFactory
                        .mapStringToLEARCredentialEmployee(vcClaim)
                        .credentialSubject()
                        .mandate()
                        .mandator()
                        .organizationIdentifier();

        return Mono.just(userOrganizationIdentifier);
    }

    public boolean isSysAdmin(String userOrganizationIdentifier) {
        return userOrganizationIdentifier.equals(appConfig.getAdminOrganizationId());
    }

    public Mono<Void> ensureSameOrgOrSysAdmin(String userOrganizationIdentifier,
                                              String credentialOrganizationIdentifier) {
        if (isSysAdmin(userOrganizationIdentifier)) {
            log.info("User belongs to admin organization. Skipping organization match.");
            return Mono.empty();
        }

        if (userOrganizationIdentifier.equals(credentialOrganizationIdentifier)) {
            return Mono.empty();
        }

        return Mono.error(new UnauthorizedRoleException("Access denied: Unauthorized organization identifier"));
    }

    private Mono<SignedJWT> parseToken(String token) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token));
    }

    private Mono<String> extractRole(SignedJWT signedJWT) {
        try {
            String role = (String) signedJWT.getJWTClaimsSet().getClaim(ROLE_CLAIM);
            log.debug("Extracted role: {}", role);
            return Mono.just(role);
        } catch (ParseException e) {
            return Mono.error(new JWTParsingException(e.getMessage()));
        }
    }

    private Mono<Void> ensureRoleIs(String actualRole, String requiredRole) {
        if (!requiredRole.equals(actualRole)) {
            return Mono.error(new UnauthorizedRoleException(
                    "Access denied: Unauthorized role to perform this credential action"
            ));
        }
        return Mono.empty();
    }
}

