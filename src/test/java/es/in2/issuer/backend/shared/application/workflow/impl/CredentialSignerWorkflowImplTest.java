package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdp;
import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.JWT_VC;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialSignerWorkflowImplTest {
    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private BackofficePdp backofficePdp;

    @Mock
    private RemoteSignatureService remoteSignatureService;

    @Mock
    private DeferredCredentialWorkflow deferredCredentialWorkflow;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Mock
    private LabelCredentialFactory labelCredentialFactory;

    @Mock
    private IssuerFactory issuerFactory;

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @Mock
    private M2MTokenService m2mTokenService;

    @Mock
    private CredentialDeliveryService credentialDeliveryService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private SimpleIssuer simpleIssuer;

    @Mock
    private VerifierOauth2AccessToken verifierOauth2AccessToken;

    @Spy
    @InjectMocks
    CredentialSignerWorkflowImpl credentialSignerWorkflow;

    private final String processId = "process-123";
    private final String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
    private final String authorizationHeader = "Bearer some-token";
    private final String token = "some-token";
    private final String email = "alice@example.com";
    private final String organizationId = "org-123";
    private final String bindedCredential = "bindedCredential";

    @Test
    void testRetrySignUnsignedCredential_Success_LEARCredentialEmployee() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        // Mock token extraction and validation
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));

        // Mock repository and service calls
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.empty());
        doReturn(Mono.just("signedCredential"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any())).thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdp).validateSignCredential(processId, token, procedureId);
        verify(learCredentialEmployeeFactory).mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email);
        verify(credentialProcedureService).updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC);
        verify(credentialSignerWorkflow).signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        verify(credentialProcedureService).updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
    }

    @Test
    void testRetrySignUnsignedCredential_ThrowsWhenProcedureNotFound() {
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .expectErrorMessage("Procedure not found")
                .verify();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdp).validateSignCredential(processId, token, procedureId);
        verifyNoInteractions(learCredentialEmployeeFactory);
    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnMappingCredential() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email))
                .thenReturn(Mono.error(new RuntimeException("Mapping failed")));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .expectErrorMessage("Mapping failed")
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_DefaultCase_ThrowsIllegalArgument() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn("UNKNOWN_TYPE");
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalArgumentException &&
                                throwable.getMessage().contains("Unsupported credential type: UNKNOWN_TYPE")
                )
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_LabelCredential_SendsVcToResponseUri() {
        // First find(): mapping + update decoded
        CredentialProcedure initialProcedure = mock(CredentialProcedure.class);
        when(initialProcedure.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(initialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        // Second find(): after signing and updating as VALID
        CredentialProcedure updatedProcedure = mock(CredentialProcedure.class);
        when(updatedProcedure.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(updatedProcedure.getEmail()).thenReturn("foo@bar.com");

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(initialProcedure), Mono.just(updatedProcedure));

        // Map issuer -> bind VC -> update decoded
        when(issuerFactory.createSimpleIssuer(procedureId, email))
                .thenReturn(Mono.just(simpleIssuer));
        when(labelCredentialFactory.mapIssuer(procedureId, simpleIssuer))
                .thenReturn(Mono.just("bindedVc"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC))
                .thenReturn(Mono.empty());

        // Signature and update state
        doReturn(Mono.just("signedVc"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());

        // Save updatedAt
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(updatedProcedure));

        // Send VC: responseUri + token + delivery
        String credentialId = "cred-id-123";
        when(credentialProcedureService.getCredentialId(updatedProcedure))
                .thenReturn(Mono.just(credentialId));
        when(deferredCredentialMetadataService.getResponseUriByProcedureId(procedureId))
                .thenReturn(Mono.just("https://callback.example.com"));
        when(m2mTokenService.getM2MToken())
                .thenReturn(Mono.just(verifierOauth2AccessToken));
        when(verifierOauth2AccessToken.accessToken()).thenReturn("access-token");
        when(credentialDeliveryService.sendVcToResponseUri(
                "https://callback.example.com",
                "signedVc",
                credentialId,
                "foo@bar.com",
                "access-token"
        )).thenReturn(Mono.empty());

        // Execution
        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .verifyComplete();

        // Verify
        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdp).validateSignCredential(processId, token, procedureId);
        verify(issuerFactory).createSimpleIssuer(procedureId, email);
        verify(labelCredentialFactory).mapIssuer(procedureId, simpleIssuer);
        verify(credentialProcedureService).updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC);
        verify(credentialSignerWorkflow).signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        verify(credentialProcedureService).updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
        verify(credentialDeliveryService).sendVcToResponseUri(
                "https://callback.example.com",
                "signedVc",
                credentialId,
                "foo@bar.com",
                "access-token"
        );
    }

    @Test
    void testRetrySignUnsignedCredential_LabelCredential_NoResponseUri_ThrowsError() {
        CredentialProcedure initialProcedure = mock(CredentialProcedure.class);
        when(initialProcedure.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(initialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProcedure updatedProcedure = mock(CredentialProcedure.class);
        when(updatedProcedure.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(initialProcedure), Mono.just(updatedProcedure));

        when(issuerFactory.createSimpleIssuer(procedureId, email))
                .thenReturn(Mono.just(simpleIssuer));
        when(labelCredentialFactory.mapIssuer(procedureId, simpleIssuer))
                .thenReturn(Mono.just("bindedVc"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC))
                .thenReturn(Mono.empty());

        doReturn(Mono.just("signedVc"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(updatedProcedure));

        // No responseUri available
        when(deferredCredentialMetadataService.getResponseUriByProcedureId(procedureId))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalStateException &&
                                throwable.getMessage().contains("Missing responseUri for procedureId")
                )
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_NonLabelCredential_DoesNotSendVc() {
        CredentialProcedure initialProcedure = mock(CredentialProcedure.class);
        when(initialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);
        when(initialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(initialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProcedure updatedProcedure = mock(CredentialProcedure.class);
        when(updatedProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(initialProcedure), Mono.just(updatedProcedure));

        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.empty());

        doReturn(Mono.just("signedVc"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(updatedProcedure));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .verifyComplete();

        // Verify that credential delivery was NOT called
        verifyNoInteractions(deferredCredentialMetadataService);
        verifyNoInteractions(m2mTokenService);
        verifyNoInteractions(credentialDeliveryService);
    }

    @Test
    void testRetrySignUnsignedCredential_ValidationFails() {
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.error(new RuntimeException("Validation failed")));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .expectErrorMessage("Validation failed")
                .verify();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdp).validateSignCredential(processId, token, procedureId);
        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void testRetrySignUnsignedCredential_StatusNotPendSignature_ThrowsIllegalState() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        // Simulate a status different from PEND_SIGNATURE (null will also fail the filter)
        when(credentialProcedure.getCredentialStatus()).thenReturn(null);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdp.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalStateException &&
                                throwable.getMessage().contains("is not in PEND_SIGNATURE status")
                )
                .verify();

        verify(credentialProcedureRepository).findByProcedureId(UUID.fromString(procedureId));
        verifyNoInteractions(learCredentialEmployeeFactory);
        verifyNoInteractions(issuerFactory);
    }
}
