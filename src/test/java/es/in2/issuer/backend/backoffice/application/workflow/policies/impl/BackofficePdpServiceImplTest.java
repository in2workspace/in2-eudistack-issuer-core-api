package es.in2.issuer.backend.backoffice.application.workflow.policies.impl;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
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

import static es.in2.issuer.backend.backoffice.domain.util.Constants.LEAR;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.ROLE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.VC;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BackofficePdpServiceImplTest {

    @Mock
    private AppConfig appConfig;

    @Mock
    private JWTService jwtService;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @InjectMocks
    private BackofficePdpServiceImpl backofficePdp;

    private SignedJWT buildSignedJwtWithRoleAndOrg(String role, String orgId) throws Exception {
        SignedJWT signedJWT = mock(SignedJWT.class);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim(ROLE, role)
                .build();
        when(signedJWT.getJWTClaimsSet()).thenReturn(claimsSet);

        Payload payload = new Payload("vc-json");
        when(signedJWT.getPayload()).thenReturn(payload);

        when(jwtService.getClaimFromPayload(payload, VC)).thenReturn("vc-json");

        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class, RETURNS_DEEP_STUBS);
        when(learCredentialEmployee
                .credentialSubject()
                .mandate()
                .mandator()
                .organizationIdentifier())
                .thenReturn(orgId);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vc-json"))
                .thenReturn(learCredentialEmployee);

        return signedJWT;
    }

    @Test
    void validateSignCredential_adminOrg_skipsDbLookup() throws Exception {
        String token = "token";
        String adminOrgId = "admin-org";
        String procedureId = UUID.randomUUID().toString();

        SignedJWT signedJWT = buildSignedJwtWithRoleAndOrg(LEAR, adminOrgId);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(appConfig.getAdminOrganizationId()).thenReturn(adminOrgId);

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result).verifyComplete();

        verify(jwtService).parseJWT(token);
        verify(appConfig).getAdminOrganizationId();
        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void validateRevokeCredential_nonAdmin_matchingOrg_allows() throws Exception {
        String token = "token";
        String adminOrgId = "admin-org";
        String userOrgId = "org-123";
        String procedureId = UUID.randomUUID().toString();

        SignedJWT signedJWT = buildSignedJwtWithRoleAndOrg(LEAR, userOrgId);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(appConfig.getAdminOrganizationId()).thenReturn(adminOrgId);

        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getOrganizationIdentifier()).thenReturn(userOrgId);

        when(credentialProcedureRepository.findById(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        Mono<Void> result = backofficePdp.validateRevokeCredential("process", token, procedureId);

        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureRepository).findById(UUID.fromString(procedureId));
    }

    @Test
    void validateSendReminder_nonAdmin_orgMismatch_denied() throws Exception {
        String token = "token";
        String adminOrgId = "admin-org";
        String userOrgId = "org-123";
        String procedureId = UUID.randomUUID().toString();

        SignedJWT signedJWT = buildSignedJwtWithRoleAndOrg(LEAR, userOrgId);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(appConfig.getAdminOrganizationId()).thenReturn(adminOrgId);

        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getOrganizationIdentifier()).thenReturn("other-org");

        when(credentialProcedureRepository.findById(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        Mono<Void> result = backofficePdp.validateSendReminder("process", token, procedureId);

        StepVerifier.create(result)
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void validateCommon_unauthorizedRole_throwsUnauthorizedRoleException() throws Exception {
        String token = "token";
        String procedureId = UUID.randomUUID().toString();

        SignedJWT signedJWT = buildSignedJwtWithRoleOnly("NOT_LEAR");

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result)
                .expectError(UnauthorizedRoleException.class)
                .verify();

        verifyNoInteractions(credentialProcedureRepository);
    }


    @Test
    void validateCommon_jwtClaimsParseError_throwsJWTParsingException() throws Exception {
        String token = "token";
        String procedureId = UUID.randomUUID().toString();

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(signedJWT.getJWTClaimsSet()).thenThrow(new ParseException("bad claims", 0));

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result)
                .expectError(JWTParsingException.class)
                .verify();

        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void validateCommon_parseTokenThrows_propagatesError(){
        String token = "token";
        String procedureId = UUID.randomUUID().toString();

        when(jwtService.parseJWT(token)).thenThrow(new RuntimeException("parse error"));

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result)
                .expectErrorMessage("parse error")
                .verify();

        verify(jwtService).parseJWT(token);
        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void validateCommon_nonAdmin_repoEmpty_completes() throws Exception {
        String token = "token";
        String adminOrgId = "admin-org";
        String userOrgId = "org-123";
        String procedureId = UUID.randomUUID().toString();

        SignedJWT signedJWT = buildSignedJwtWithRoleAndOrg(LEAR, userOrgId);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(appConfig.getAdminOrganizationId()).thenReturn(adminOrgId);

        when(credentialProcedureRepository.findById(UUID.fromString(procedureId)))
                .thenReturn(Mono.empty());

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureRepository).findById(UUID.fromString(procedureId));
    }

    //helper
    private SignedJWT buildSignedJwtWithRoleOnly(String role) throws Exception {
        SignedJWT signedJWT = mock(SignedJWT.class);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim(ROLE, role)
                .build();
        when(signedJWT.getJWTClaimsSet()).thenReturn(claimsSet);

        return signedJWT;
    }

}
