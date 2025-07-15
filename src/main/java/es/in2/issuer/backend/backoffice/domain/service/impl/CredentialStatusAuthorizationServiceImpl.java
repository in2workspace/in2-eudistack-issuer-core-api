package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.backoffice.domain.service.CredentialStatusAuthorizationService;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialStatusAuthorizationServiceImpl implements CredentialStatusAuthorizationService {

    private final JWTService jwtService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    private final CredentialProcedureRepository credentialProcedureRepository;

    @Override
    public Mono<Void> authorize(String processId, String token, String credentialId) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    Payload payload = signedJWT.getPayload();
                    String role;
                    try {
                        role = (String) signedJWT.getJWTClaimsSet().getClaim(ROLE);
                    } catch (ParseException e) {
                        throw new JWTParsingException(e.getMessage());
                    }
                    log.debug("Extracted role: {}", role);
                    Mono<Void> error = ensureRoleIsLear(role);
                    if (error != null) return error;

                    String vcClaim = jwtService.getClaimFromPayload(payload, VC);
                    log.debug("claim: {}", vcClaim);

                    //TODO: Adaptar a todo tipo de credenciales
                    String userOrganizationIdentifier =
                            learCredentialEmployeeFactory
                                    .mapStringToLEARCredentialEmployee(vcClaim)
                                    .credentialSubject()
                                    .mandate()
                                    .mandator()
                                    .organizationIdentifier();

                    return credentialProcedureRepository.findByCredentialId(UUID.fromString(credentialId))
                            .flatMap(credential -> {
                                String credentialOrganizationIdentifier = credential.getOrganizationIdentifier();
                                if (userOrganizationIdentifier.equals(IN2_ORGANIZATION_IDENTIFIER) ||
                                        userOrganizationIdentifier.equals(credentialOrganizationIdentifier)) {
                                    return Mono.empty();
                                } else {
                                    return Mono.error(new UnauthorizedRoleException(
                                            "Access denied: Unauthorized organization identifier to revoke credential"));
                                }
                            });
                });
    }

    private static @Nullable Mono<Void> ensureRoleIsLear(String role) {
        if (!role.equals(LEAR)) {
            return Mono.error(new UnauthorizedRoleException(
                    "Access denied: Unauthorized role to revoke credential"));
        }
        return null;
    }
}
