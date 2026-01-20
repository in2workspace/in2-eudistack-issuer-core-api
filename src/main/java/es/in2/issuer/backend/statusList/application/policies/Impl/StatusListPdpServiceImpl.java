package es.in2.issuer.backend.statusList.application.policies.Impl;


import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.statusList.application.policies.StatusListPdpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;

// crate shared pdp package to avoid duplications with backoffic pdp
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListPdpServiceImpl implements StatusListPdpService {

    private static final String ROLE = "role";
    private static final String VC = "vc";
    private static final String LEAR = "LEAR";

    private final AccessTokenService accessTokenService;
    private final AppConfig appConfig;
    private final JWTService jwtService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Override
    public Mono<Void> validateRevokeCredential(String processId, String token, CredentialProcedure procedure) {
        return Mono.defer(() ->
                validateStatus(procedure.getCredentialStatus())
                        .doFirst(() -> log.info("Process ID: {} - Validating 'revoke' action...", processId))
                        .then(parseTokenAndValidateRole(token))
                        .flatMap(this::extractUserOrganizationIdentifier)
                        .flatMap(userOrg -> matchUserAndCredentialOrganization(userOrg, procedure.getOrganizationIdentifier()))
        );
    }


    private Mono<Void> validateStatus(CredentialStatusEnum credentialStatus) {
        if (credentialStatus == VALID) {
            return Mono.empty();
        }
        //todo move InvalidStatusException to shared
        return Mono.error(new es.in2.issuer.backend.backoffice.domain.exception.InvalidStatusException(
                "Invalid status: " + credentialStatus
        ));
    }

    private Mono<SignedJWT> parseTokenAndValidateRole(String token) {
        return parseToken(token)
                .flatMap(signedJWT ->
                        extractRole(signedJWT)
                                .flatMap(this::ensureRoleIsLear)
                                .thenReturn(signedJWT)
                );
    }

    private Mono<SignedJWT> parseToken(String token) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token));
    }

    private Mono<String> extractRole(SignedJWT signedJWT) {
        try {
            String role = (String) signedJWT.getJWTClaimsSet().getClaim(ROLE);
            log.debug("Extracted role: {}", role);
            return Mono.just(role);
        } catch (ParseException e) {
            return Mono.error(new JWTParsingException(e.getMessage()));
        }
    }

    private Mono<String> extractUserOrganizationIdentifier(SignedJWT signedJWT) {
        Payload payload = signedJWT.getPayload();
        String vcClaim = jwtService.getClaimFromPayload(payload, VC);

        String userOrganizationIdentifier =
                learCredentialEmployeeFactory
                        .mapStringToLEARCredentialEmployee(vcClaim)
                        .credentialSubject()
                        .mandate()
                        .mandator()
                        .organizationIdentifier();

        return Mono.just(userOrganizationIdentifier);
    }

    private Mono<Void> matchUserAndCredentialOrganization(String userOrganizationIdentifier,
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

    private boolean isSysAdmin(String userOrganizationIdentifier) {
        return userOrganizationIdentifier.equals(appConfig.getAdminOrganizationId());
    }

    private Mono<Void> ensureRoleIsLear(String role) {
        if (!LEAR.equals(role)) {
            return Mono.error(new UnauthorizedRoleException(
                    "Access denied: Unauthorized role to perform this credential action"
            ));
        }
        return Mono.empty();
    }
}
