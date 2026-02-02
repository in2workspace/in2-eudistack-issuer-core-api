package es.in2.issuer.backend.statuslist.application.policies.impl;


import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.backoffice.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.statuslist.application.policies.StatusListPdpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListPdpServiceImpl implements StatusListPdpService {

    private final AppConfig appConfig;
    private final JWTService jwtService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Override
    public Mono<Void> validateRevokeCredential(String processId,
                                               String token,
                                               CredentialProcedure procedure) {

        return Mono.defer(() ->
                validateStatus(procedure.getCredentialStatus())
                        .doFirst(() ->
                                log.info(
                                        "Process ID: {} - Validating 'revoke' action...",
                                        processId
                                )
                        )
                        .then(parseAndValidateRole(token, LEAR))
                        .flatMap(this::extractUserOrganizationIdentifier)
                        .flatMap(userOrg ->
                                ensureSameOrgOrSysAdmin(
                                        userOrg,
                                        procedure.getOrganizationIdentifier()
                                )
                        )
        );
    }

    @Override
    public Mono<Void> validateRevokeCredentialSystem(String processId, CredentialProcedure procedure) {
        return Mono.defer(() ->
                validateStatus(procedure.getCredentialStatus())
                        .doFirst(() ->
                                log.info(
                                        "Process ID: {} - Validating 'revoke' action (system)...",
                                        processId
                                )
                        )
        );
    }


    /* ---------- Status validation ---------- */

    private Mono<Void> validateStatus(CredentialStatusEnum credentialStatus) {
        if (credentialStatus == VALID) {
            return Mono.empty();
        }

        return Mono.error(
                new InvalidStatusException("Invalid status: " + credentialStatus)
        );
    }

    /* ---------- Role & token ---------- */

    private Mono<SignedJWT> parseAndValidateRole(String token, String requiredRole) {
        return parseToken(token)
                .flatMap(jwt ->
                        extractRole(jwt)
                                .flatMap(role -> ensureRoleIs(role, requiredRole))
                                .thenReturn(jwt)
                );
    }

    private Mono<SignedJWT> parseToken(String token) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token));
    }

    private Mono<String> extractRole(SignedJWT signedJWT) {
        try {
            String role = (String) signedJWT
                    .getJWTClaimsSet()
                    .getClaim(ROLE);

            log.debug("Extracted role: {}", role);
            return Mono.just(role);

        } catch (ParseException e) {
            return Mono.error(new JWTParsingException(e.getMessage()));
        }
    }

    private Mono<Void> ensureRoleIs(String actualRole, String requiredRole) {
        if (!requiredRole.equals(actualRole)) {
            return Mono.error(
                    new UnauthorizedRoleException(
                            "Access denied: Unauthorized role to perform this credential action"
                    )
            );
        }
        return Mono.empty();
    }

    /* ---------- Organization ---------- */

    private Mono<String> extractUserOrganizationIdentifier(SignedJWT signedJWT) {
        Payload payload = signedJWT.getPayload();
        String vcClaim = jwtService.getClaimFromPayload(payload, VC);

        String organizationIdentifier =
                learCredentialEmployeeFactory
                        .mapStringToLEARCredentialEmployee(vcClaim)
                        .credentialSubject()
                        .mandate()
                        .mandator()
                        .organizationIdentifier();

        return Mono.just(organizationIdentifier);
    }

    private Mono<Void> ensureSameOrgOrSysAdmin(String userOrg,
                                               String credentialOrg) {

        if (isSysAdmin(userOrg)) {
            log.info("User belongs to admin organization. Skipping organization match.");
            return Mono.empty();
        }

        if (userOrg.equals(credentialOrg)) {
            return Mono.empty();
        }

        return Mono.error(
                new UnauthorizedRoleException(
                        "Access denied: Unauthorized organization identifier"
                )
        );
    }

    private boolean isSysAdmin(String organizationIdentifier) {
        return organizationIdentifier.equals(appConfig.getAdminOrganizationId());
    }
}
