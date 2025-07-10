package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.text.ParseException;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialStatusAuthorizationServiceImplTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @Mock
    private SignedJWT signedJWT;

    @Mock
    private Payload payload;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @InjectMocks
    private CredentialStatusAuthorizationServiceImpl authorizationService;

    private static final String PROCESS_ID = "test-process-id";
    private static final String TOKEN = "test-token";
    private static final String CREDENTIAL_ID = "550e8400-e29b-41d4-a716-446655440000";
    private static final String VC_CLAIM = "test-vc-claim";

    @Test
    void authorize_WithValidLearRoleAndMatchingOrganization_ShouldSucceed() throws ParseException {
        String organizationIdentifier = "organization-identifier";
        LEARCredentialEmployee learCredentialEmployee =
                LEARCredentialEmployee.builder()
                        .credentialSubject(
                                LEARCredentialEmployee.CredentialSubject.builder()
                                        .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                                                .mandator(Mandator.builder()
                                                        .organizationIdentifier(organizationIdentifier)
                                                        .build())
                                                .build())
                                        .build()
                        )
                        .build();

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);

        when(jwtService.parseJWT(TOKEN))
                .thenReturn(signedJWT);
        when(signedJWT.getPayload())
                .thenReturn(payload);
        JWTClaimsSet jwtClaimsSet = mock(JWTClaimsSet.class);
        when(signedJWT.getJWTClaimsSet()).thenReturn(jwtClaimsSet);
        when(jwtClaimsSet.getClaim(ROLE)).thenReturn(LEAR);

        when(jwtService.getClaimFromPayload(payload, VC))
                .thenReturn(VC_CLAIM);
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(VC_CLAIM))
                .thenReturn(learCredentialEmployee);
        when(credentialProcedureRepository.findByCredentialId(UUID.fromString(CREDENTIAL_ID)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier
                .create(authorizationService.authorize(PROCESS_ID, TOKEN, CREDENTIAL_ID))
                .verifyComplete();

        verify(jwtService).parseJWT(TOKEN);
        verify(jwtClaimsSet).getClaim(ROLE);
        verify(jwtService).getClaimFromPayload(payload, VC);
        verify(credentialProcedureRepository).findByCredentialId(UUID.fromString(CREDENTIAL_ID));
    }

    @Test
    void authorize_WithValidLearRoleAndIn2OrganizationIdentifier_ShouldSucceed() throws ParseException {
        LEARCredentialEmployee learCredentialEmployee =
                LEARCredentialEmployee.builder()
                        .credentialSubject(
                                LEARCredentialEmployee.CredentialSubject.builder()
                                        .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                                                .mandator(Mandator.builder()
                                                        .organizationIdentifier(IN2_ORGANIZATION_IDENTIFIER)
                                                        .build())
                                                .build())
                                        .build()
                        )
                        .build();

        CredentialProcedure credentialProcedure = new CredentialProcedure();

        when(jwtService.parseJWT(TOKEN))
                .thenReturn(signedJWT);
        when(signedJWT.getPayload())
                .thenReturn(payload);
        JWTClaimsSet jwtClaimsSet = mock(JWTClaimsSet.class);
        when(signedJWT.getJWTClaimsSet()).thenReturn(jwtClaimsSet);
        when(jwtClaimsSet.getClaim(ROLE)).thenReturn(LEAR);

        when(jwtService.getClaimFromPayload(payload, VC))
                .thenReturn(VC_CLAIM);
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(VC_CLAIM))
                .thenReturn(learCredentialEmployee);
        when(credentialProcedureRepository.findByCredentialId(UUID.fromString(CREDENTIAL_ID)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier
                .create(authorizationService.authorize(PROCESS_ID, TOKEN, CREDENTIAL_ID))
                .verifyComplete();

        verify(jwtService).parseJWT(TOKEN);
        verify(jwtClaimsSet).getClaim(ROLE);
        verify(jwtService).getClaimFromPayload(payload, VC);
        verify(credentialProcedureRepository).findByCredentialId(UUID.fromString(CREDENTIAL_ID));
    }

    @Test
    void authorize_WithInvalidRole_ShouldFailed() throws ParseException {
        String organizationIdentifier = "organization-identifier";


        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);

        when(jwtService.parseJWT(TOKEN))
                .thenReturn(signedJWT);
        when(signedJWT.getPayload())
                .thenReturn(payload);
        JWTClaimsSet jwtClaimsSet = mock(JWTClaimsSet.class);
        when(signedJWT.getJWTClaimsSet()).thenReturn(jwtClaimsSet);
        when(jwtClaimsSet.getClaim(ROLE)).thenReturn("error");

        StepVerifier
                .create(authorizationService.authorize(PROCESS_ID, TOKEN, CREDENTIAL_ID))
                .expectError(UnauthorizedRoleException.class)
                .verify();

        verify(jwtService).parseJWT(TOKEN);
    }

    @Test
    void authorize_WithValidLearRoleAndInvalidOrganizationIdentifier_ShouldFailed() throws ParseException {
        String organizationIdentifier = "organization-identifier";
        LEARCredentialEmployee learCredentialEmployee =
                LEARCredentialEmployee.builder()
                        .credentialSubject(
                                LEARCredentialEmployee.CredentialSubject.builder()
                                        .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                                                .mandator(Mandator.builder()
                                                        .organizationIdentifier(organizationIdentifier)
                                                        .build())
                                                .build())
                                        .build()
                        )
                        .build();

        CredentialProcedure credentialProcedure = new CredentialProcedure();

        when(jwtService.parseJWT(TOKEN))
                .thenReturn(signedJWT);
        when(signedJWT.getPayload())
                .thenReturn(payload);
        JWTClaimsSet jwtClaimsSet = mock(JWTClaimsSet.class);
        when(signedJWT.getJWTClaimsSet()).thenReturn(jwtClaimsSet);
        when(jwtClaimsSet.getClaim(ROLE)).thenReturn(LEAR);

        when(jwtService.getClaimFromPayload(payload, VC))
                .thenReturn(VC_CLAIM);
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(VC_CLAIM))
                .thenReturn(learCredentialEmployee);
        when(credentialProcedureRepository.findByCredentialId(UUID.fromString(CREDENTIAL_ID)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier
                .create(authorizationService.authorize(PROCESS_ID, TOKEN, CREDENTIAL_ID))
                .expectError(UnauthorizedRoleException.class)
                .verify();

        verify(jwtService).parseJWT(TOKEN);
        verify(jwtClaimsSet).getClaim(ROLE);
        verify(jwtService).getClaimFromPayload(payload, VC);
        verify(credentialProcedureRepository).findByCredentialId(UUID.fromString(CREDENTIAL_ID));
    }
}