package es.in2.issuer.backend.statuslist.application.policies.impl;


import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.backoffice.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.text.ParseException;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StatusListPdpServiceImplTest {

    @Mock
    private AppConfig appConfig;

    @Mock
    private JWTService jwtService;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    private StatusListPdpServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new StatusListPdpServiceImpl(appConfig, jwtService, learCredentialEmployeeFactory);
    }

    @Test
    void validateRevokeCredential_shouldComplete_whenValidStatus_roleLear_andSameOrganization() throws Exception {
        // Arrange
        String processId = "p-1";
        String token = "token";
        String procedureOrg = "ORG_1";
        String userOrg = "ORG_1";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);
        when(procedure.getOrganizationIdentifier()).thenReturn(procedureOrg);

        SignedJWT signedJWT = mockSignedJwtWithRole(LEAR);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);

        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, VC)).thenReturn("vc-claim");

        // Replace the next line's type/import if your project uses a different class name/package.
        // Example: es.in2.issuer.backend.shared.domain.model.lear.LEARCredentialEmployee
        LEARCredentialEmployee employee = mock(LEARCredentialEmployee.class, RETURNS_DEEP_STUBS);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vc-claim"))
                .thenReturn(employee);

        when(employee.credentialSubject()
                .mandate()
                .mandator()
                .organizationIdentifier())
                .thenReturn(userOrg);

        when(appConfig.getAdminOrganizationId()).thenReturn("ADMIN");

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential(processId, token, procedure))
                .verifyComplete();

        verify(jwtService).parseJWT(token);
        verify(jwtService).getClaimFromPayload(payload, VC);
        verify(learCredentialEmployeeFactory).mapStringToLEARCredentialEmployee("vc-claim");
    }

    @Test
    void validateRevokeCredential_shouldComplete_whenUserIsSysAdmin_evenIfOrganizationDiffers() throws Exception {
        // Arrange
        String processId = "p-2";
        String token = "token";
        String procedureOrg = "ORG_2";
        String adminOrg = "ADMIN";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);
        when(procedure.getOrganizationIdentifier()).thenReturn(procedureOrg);

        SignedJWT signedJWT = mockSignedJwtWithRole(LEAR);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);

        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, VC)).thenReturn("vc-claim");

        LEARCredentialEmployee employee = mock(LEARCredentialEmployee.class, RETURNS_DEEP_STUBS);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vc-claim"))
                .thenReturn(employee);

        when(employee.credentialSubject()
                .mandate()
                .mandator()
                .organizationIdentifier())
                .thenReturn(adminOrg);


        when(appConfig.getAdminOrganizationId()).thenReturn(adminOrg);

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential(processId, token, procedure))
                .verifyComplete();
    }

    @Test
    void validateRevokeCredential_shouldErrorInvalidStatus_whenStatusIsNotValid() {
        // Arrange
        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential("p-3", "token", procedure))
                .expectError(InvalidStatusException.class)
                .verify();

        verifyNoInteractions(jwtService);
        verifyNoInteractions(learCredentialEmployeeFactory);
    }

    @Test
    void validateRevokeCredential_shouldErrorUnauthorizedRole_whenRoleIsNotLear() throws Exception {
        // Arrange
        String token = "token";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);

        SignedJWT signedJWT = mockSignedJwtWithRole("SOME_OTHER_ROLE");
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential("p-4", token, procedure))
                .expectError(UnauthorizedRoleException.class)
                .verify();

        verify(jwtService).parseJWT(token);
        verifyNoMoreInteractions(jwtService);
        verifyNoInteractions(learCredentialEmployeeFactory);
    }

    @Test
    void validateRevokeCredential_shouldErrorJwtParsingException_whenClaimsCannotBeParsed() throws Exception {
        // Arrange
        String token = "token";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(signedJWT.getJWTClaimsSet()).thenThrow(new ParseException("boom", 0));

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential("p-5", token, procedure))
                .expectError(JWTParsingException.class)
                .verify();

        verify(jwtService).parseJWT(token);
        verifyNoInteractions(learCredentialEmployeeFactory);
    }

    @Test
    void validateRevokeCredential_shouldErrorUnauthorizedRole_whenOrganizationDiffersAndNotSysAdmin() throws Exception {
        // Arrange
        String token = "token";
        String procedureOrg = "ORG_A";
        String userOrg = "ORG_B";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);
        when(procedure.getOrganizationIdentifier()).thenReturn(procedureOrg);

        SignedJWT signedJWT = mockSignedJwtWithRole(LEAR);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);

        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, VC)).thenReturn("vc-claim");

        LEARCredentialEmployee employee = mock(LEARCredentialEmployee.class, RETURNS_DEEP_STUBS);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vc-claim"))
                .thenReturn(employee);

        when(employee.credentialSubject()
                .mandate()
                .mandator()
                .organizationIdentifier())
                .thenReturn(userOrg);

        when(appConfig.getAdminOrganizationId()).thenReturn("ADMIN");

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential("p-6", token, procedure))
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void validateRevokeCredentialSystem_shouldComplete_whenValidStatus() {
        // Arrange
        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredentialSystem("p-7", procedure))
                .verifyComplete();

        verifyNoInteractions(jwtService);
        verifyNoInteractions(learCredentialEmployeeFactory);
    }

    @Test
    void validateRevokeCredentialSystem_shouldErrorInvalidStatus_whenNotValid() {
        // Arrange
        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredentialSystem("p-8", procedure))
                .expectError(InvalidStatusException.class)
                .verify();

        verifyNoInteractions(jwtService);
        verifyNoInteractions(learCredentialEmployeeFactory);
    }

    private SignedJWT mockSignedJwtWithRole(String role) throws Exception {
        SignedJWT signedJWT = mock(SignedJWT.class);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim(ROLE, role)
                .build();

        when(signedJWT.getJWTClaimsSet()).thenReturn(claimsSet);
        return signedJWT;
    }

}
