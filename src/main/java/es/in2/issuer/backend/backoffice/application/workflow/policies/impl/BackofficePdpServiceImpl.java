package es.in2.issuer.backend.backoffice.application.workflow.policies.impl;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.LEAR;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.ROLE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.VC;

@Service
@Slf4j
@RequiredArgsConstructor
public class BackofficePdpServiceImpl implements BackofficePdpService {

    private final AppConfig appConfig;
    private final JWTService jwtService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    private final CredentialProcedureRepository credentialProcedureRepository;

    @Override
    public Mono<Void> validateSignCredential(String processId, String token, String credentialProcedureId) {
        log.info("Validating 'sign' action for processId={} and credentialProcedureId={}", processId, credentialProcedureId);
        return validateCommon(token, credentialProcedureId);
    }

    @Override
    public Mono<Void> validateRevokeCredential(String processId, String token, String credentialProcedureId) {
        log.info("Validating 'revoke' action for processId={} and credentialProcedureId={}", processId, credentialProcedureId);
        return validateCommon(token, credentialProcedureId);
    }

    @Override
    public Mono<Void> validateSendReminder(String processId, String token, String credentialProcedureId) {
        log.info("Validating 'send reminder' action for processId={} and credentialProcedureId={}", processId, credentialProcedureId);
        return validateCommon(token, credentialProcedureId);
    }

    private Mono<Void> validateCommon(String token, String credentialProcedureId) {
        return parseTokenAndValidateRole(token)
                .flatMap(signedJWT ->
                        extractUserOrganizationIdentifier(signedJWT)
                                .flatMap(userOrg -> {

                                    if (isSysAdmin(userOrg)) {
                                        log.info("User belongs to admin organization. Skipping DB lookup.");
                                        return Mono.empty();
                                    }

                                    return credentialProcedureRepository.findById(UUID.fromString(credentialProcedureId))
                                            .flatMap(credentialProcedure ->
                                                    matchUserAndCredentialOrganization(
                                                            userOrg,
                                                            credentialProcedure.getOrganizationIdentifier()
                                                    )
                                            );
                                })
                );
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
            log.info("Extracted role: {}", role);
            return Mono.just(role);
        } catch (ParseException e) {
            return Mono.error(new JWTParsingException(e.getMessage()));
        }
    }

    private Mono<String> extractUserOrganizationIdentifier(SignedJWT signedJWT) {
        Payload payload = signedJWT.getPayload();
        String vcClaim = jwtService.getClaimFromPayload(payload, VC);
        log.debug("VC claim: {}", vcClaim);

        // TODO: Adapt to all credential types if needed
        String userOrganizationIdentifier =
                learCredentialEmployeeFactory
                        .mapStringToLEARCredentialEmployee(vcClaim)
                        .credentialSubject()
                        .mandate()
                        .mandator()
                        .organizationIdentifier();

        log.info("User organization identifier: {}", userOrganizationIdentifier);
        return Mono.just(userOrganizationIdentifier);
    }

    private boolean isSysAdmin(String userOrganizationIdentifier) {
        return userOrganizationIdentifier.equals(appConfig.getAdminOrganizationId());
    }

    private Mono<Void> matchUserAndCredentialOrganization(String userOrganizationIdentifier,
                                                          String credentialOrganizationIdentifier) {

        if (userOrganizationIdentifier.equals(credentialOrganizationIdentifier)) {
            return Mono.empty();
        }

        return Mono.error(
                new UnauthorizedRoleException("Access denied: Unauthorized organization identifier")
        );
    }

    private Mono<Void> ensureRoleIsLear(String role) {
        if (!LEAR.equals(role)) {
            return Mono.error(new UnauthorizedRoleException(
                    "Access denied: Unauthorized role to perform this credential action"));
        }
        return Mono.empty();
    }
}
