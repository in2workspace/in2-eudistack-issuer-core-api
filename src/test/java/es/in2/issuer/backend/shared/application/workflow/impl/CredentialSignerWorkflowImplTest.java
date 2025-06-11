package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.LabelCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
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

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CWT_VC;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.JWT_VC;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialSignerWorkflowImplTest {
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
    CredentialProcedureRepository credentialProcedureRepository;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @Mock
    private M2MTokenService m2mTokenService;

    @Mock
    private CredentialDeliveryService credentialDeliveryService;

    @Mock
    private DetailedIssuer detailedIssuer;

    @Mock
    private VerifierOauth2AccessToken verifierOauth2AccessToken;

    @Spy
    @InjectMocks
    CredentialSignerWorkflowImpl credentialSignerWorkflow;

    private final String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
    private final String authorizationHeader = "Bearer some-token";
    private final String bindedCredential = "bindedCredential";


    @Test
    void signCredentialOnRequestedFormat_JWT_Success() {
        String unsignedCredential = "unsignedCredential";
        String token = "dummyToken";
        String signedCredential = "signedJWTData";
        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialDecoded(unsignedCredential);
        credentialProcedure.setCredentialType(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);
        when(remoteSignatureService.sign(any(SignatureRequest.class), eq(token), eq(procedureId)))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES,signedCredential)));

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(unsignedCredential)).thenReturn(LEARCredentialEmployee .builder().build());
        when(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(any(LEARCredentialEmployee.class)))
                .thenReturn(Mono.just(LEARCredentialEmployeeJwtPayload.builder().build()));
        when(learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(any(LEARCredentialEmployeeJwtPayload.class)))
                .thenReturn(Mono.just(unsignedCredential));

        when(deferredCredentialWorkflow.updateSignedCredentials(any(SignedCredentials.class))).thenReturn(Mono.empty());
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))).thenReturn(Mono.just(credentialProcedure));
        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC))
                .assertNext(signedData -> assertEquals(signedCredential, signedData))
                .verifyComplete();
    }
    @Test
    void signCredentialOnRequestedFormat_CWT_Success() {
        String unsignedCredential = "{\"data\":\"data\"}";
        String token = "dummyToken";
        String signedCredential = "eyJkYXRhIjoiZGF0YSJ9";
        String signedResult = "6BFWTLRH9.Q5$VAFLGV*M7:43S0";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialDecoded(unsignedCredential);
        credentialProcedure.setCredentialType(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);

        when(remoteSignatureService.sign(any(SignatureRequest.class), eq(token), eq("")))
                .thenReturn(Mono.just(new SignedData(SignatureType.COSE, signedCredential)));

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(unsignedCredential)).thenReturn(LEARCredentialEmployee .builder().build());
        when(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(any(LEARCredentialEmployee.class)))
                .thenReturn(Mono.just(LEARCredentialEmployeeJwtPayload.builder().build()));
        when(learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(any(LEARCredentialEmployeeJwtPayload.class)))
                .thenReturn(Mono.just(unsignedCredential));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))).thenReturn(Mono.just(credentialProcedure));        when(deferredCredentialWorkflow.updateSignedCredentials(any(SignedCredentials.class))).thenReturn(Mono.empty());

        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procedureId, CWT_VC))
                .assertNext(signedData -> assertEquals(signedResult, signedData))
                .verifyComplete();
    }

    @Test
    void signCredentialOnRequestedFormat_UnsupportedFormat() {
        String unsignedCredential = "unsignedCredential";
        String token = "dummyToken";
        String unsupportedFormat = "unsupportedFormat";
        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialDecoded(unsignedCredential);
        credentialProcedure.setCredentialType(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))).thenReturn(Mono.just(credentialProcedure));
        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procedureId, unsupportedFormat))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void signCredentialWithVcAlreadyPresent_Success() {
        String unsignedCredential = "{\"vc\":{\"id\":\"123\"}}"; // Contiene "vc"
        String signedCredential = "signedJWTData";
        String token = "dummyToken";
        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialDecoded(unsignedCredential);
        credentialProcedure.setCredentialType(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);

        when(remoteSignatureService.sign(any(SignatureRequest.class), eq(token), eq(procedureId)))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, signedCredential)));
        when(deferredCredentialWorkflow.updateSignedCredentials(any(SignedCredentials.class))).thenReturn(Mono.empty());
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))).thenReturn(Mono.just(credentialProcedure));
        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC))
                .assertNext(result -> assertEquals(signedCredential, result))
                .verifyComplete();

        verify(remoteSignatureService).sign(any(SignatureRequest.class), eq(token), eq(procedureId));
        verify(deferredCredentialWorkflow).updateSignedCredentials(any(SignedCredentials.class));
    }

    @Test
    void signVerifiableCertificationCredential_Success() {
        String decodedCredential = "{\"VerifiableCertification\":\"data\"}";
        String unsignedJwtPayload = "unsignedPayload";
        String signedCredential = "signedJWTData";
        String token = "dummyToken";
        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialDecoded(decodedCredential);
        credentialProcedure.setCredentialType(VERIFIABLE_CERTIFICATION_CREDENTIAL_TYPE);
        LabelCredential mockCertification = LabelCredential.builder().build();
        LabelCredentialJwtPayload mockVerifiablePayload = mock(LabelCredentialJwtPayload.class);

        when(labelCredentialFactory.mapStringToVerifiableCertification(decodedCredential)).thenReturn(mockCertification);
        when(labelCredentialFactory.buildVerifiableCertificationJwtPayload(mockCertification)).thenReturn(Mono.just(mockVerifiablePayload));
        when(labelCredentialFactory.convertVerifiableCertificationJwtPayloadInToString(any(LabelCredentialJwtPayload.class)))
                .thenReturn(Mono.just(unsignedJwtPayload));
        when(remoteSignatureService.sign(any(SignatureRequest.class), eq(token), eq(procedureId)))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, signedCredential)));
        when(deferredCredentialWorkflow.updateSignedCredentials(any(SignedCredentials.class))).thenReturn(Mono.empty());
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))).thenReturn(Mono.just(credentialProcedure));
        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC))
                .assertNext(result -> assertEquals(signedCredential, result))
                .verifyComplete();

        verify(labelCredentialFactory).mapStringToVerifiableCertification(decodedCredential);
        verify(labelCredentialFactory).buildVerifiableCertificationJwtPayload(any(LabelCredential.class));
        verify(remoteSignatureService).sign(any(SignatureRequest.class), eq(token), eq(procedureId));
        verify(deferredCredentialWorkflow).updateSignedCredentials(any(SignedCredentials.class));
    }

    @Test
    void signLEARCredentialEmployee_Success() {
        String decodedCredential = "{\"LEARCredentialEmployee\":\"data\"}";
        String unsignedJwtPayload = "unsignedPayload";
        String signedCredential = "signedJWTData";
        String token = "dummyToken";
        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialDecoded(decodedCredential);
        credentialProcedure.setCredentialType(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);

        LEARCredentialEmployee mockEmployee = LEARCredentialEmployee.builder().build();
        LEARCredentialEmployeeJwtPayload mockLearPayload = mock(LEARCredentialEmployeeJwtPayload.class);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential)).thenReturn(mockEmployee);
        when(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(mockEmployee)).thenReturn(Mono.just(mockLearPayload));
        when(learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(any(LEARCredentialEmployeeJwtPayload.class)))
                .thenReturn(Mono.just(unsignedJwtPayload));
        when(remoteSignatureService.sign(any(SignatureRequest.class), eq(token), eq(procedureId)))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, signedCredential)));
        when(deferredCredentialWorkflow.updateSignedCredentials(any(SignedCredentials.class))).thenReturn(Mono.empty());
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))).thenReturn(Mono.just(credentialProcedure));
        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC))
                .assertNext(result -> assertEquals(signedCredential, result))
                .verifyComplete();

        verify(learCredentialEmployeeFactory).mapStringToLEARCredentialEmployee(decodedCredential);
        verify(learCredentialEmployeeFactory).buildLEARCredentialEmployeeJwtPayload(any(LEARCredentialEmployee.class));
        verify(remoteSignatureService).sign(any(SignatureRequest.class), eq(token), eq(procedureId));
        verify(deferredCredentialWorkflow).updateSignedCredentials(any(SignedCredentials.class));
    }

    @Test
    void signCredential_ErrorDuringJwtPayloadCreation() {
        String decodedCredential = "{\"VerifiableCertification\":\"data\"}";
        String token = "dummyToken";
        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialDecoded(decodedCredential);
        credentialProcedure.setCredentialType(VERIFIABLE_CERTIFICATION_CREDENTIAL_TYPE);

        when(labelCredentialFactory.mapStringToVerifiableCertification(decodedCredential))
                .thenThrow(new RuntimeException("Mapping error"));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))).thenReturn(Mono.just(credentialProcedure));
        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC))
                .expectError(IllegalArgumentException.class)
                .verify();

        verify(labelCredentialFactory).mapStringToVerifiableCertification(decodedCredential);
        verify(remoteSignatureService, never()).sign(any(SignatureRequest.class), eq(token), eq(procedureId));
        verify(deferredCredentialWorkflow, never()).updateSignedCredentials(any(SignedCredentials.class));
    }
    @Test
    void testRetrySignUnsignedCredential_Success() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);


        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.empty());
        doReturn(Mono.just("true"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(authorizationHeader, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(credentialProcedureRepository.save(any())).thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId))
                .verifyComplete();

        verify(learCredentialEmployeeFactory).mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId);
        verify(credentialProcedureService).updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC);
        verify(credentialSignerWorkflow).signAndUpdateCredentialByProcedureId(authorizationHeader, procedureId, JWT_VC);
        verify(credentialProcedureService).updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
        verify(credentialProcedureRepository, times(2)).findByProcedureId(UUID.fromString(procedureId));
        verify(credentialProcedureRepository).save(any());
    }

    @Test
    void testRetrySignUnsignedCredential_ThrowsWhenProcedureNotFound() {
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId))
                .expectErrorMessage("Procedure not found")
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnMappingCredential() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId))
                .thenReturn(Mono.error(new RuntimeException("Mapping failed")));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId))
                .expectErrorMessage("Mapping failed")
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnUpdatingDecodedCredential() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);


        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.error(new RuntimeException("Failed to update decoded credential")));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId))
                .expectErrorMessage("Failed to update decoded credential")
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnSigningCredential() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);


        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(any(), eq(procedureId)))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.empty());
        doReturn(Mono.error(new RuntimeException("Signing failed")))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(authorizationHeader, procedureId, JWT_VC);

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId))
                .expectErrorMessage("Signing failed")
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnSavingUpdatedAt() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE);


        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(any(), eq(procedureId)))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.empty());
        doReturn(Mono.just("signedCredential"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(authorizationHeader, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.error(new RuntimeException("Failed to update updatedAt")));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId))
                .expectErrorMessage("Failed to update updatedAt")
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_VerifiableCertification_Success() {
        // Mocks bàsics
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn(VERIFIABLE_CERTIFICATION_CREDENTIAL_TYPE);
        // simulant el JSON cridat després per enviar el VC
        String decodedJson = """
            {
              "credentialSubject": {
                "product": { "productId": "prod-123" },
                "company": { "email": "foo@bar.com" }
              }
            }
            """;
        when(credentialProcedure.getCredentialDecoded()).thenReturn(decodedJson);

        // Flux principal
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(issuerFactory.createDetailedIssuer(procedureId, LABEL_CREDENTIAL))
                .thenReturn(Mono.just(detailedIssuer));

        when(labelCredentialFactory.mapIssuerAndSigner(procedureId, detailedIssuer))
                .thenReturn(Mono.just("bindedVc"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC))
                .thenReturn(Mono.empty());
        // signAndUpdateCredential
        doReturn(Mono.just("signedVc"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(authorizationHeader, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        // després del .then()
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(credentialProcedure));
        // enviament VC
        when(deferredCredentialMetadataService.getResponseUriByProcedureId(procedureId))
                .thenReturn(Mono.just("https://callback.example.com"));
        when(m2mTokenService.getM2MToken())
                .thenReturn(Mono.just(verifierOauth2AccessToken));
        when(verifierOauth2AccessToken.accessToken()).thenReturn("access-token");
        when(credentialDeliveryService.sendVcToResponseUri(
                "https://callback.example.com",
                "signedVc",
                "prod-123",
                "foo@bar.com",
                "access-token"))
                .thenReturn(Mono.empty());

        // Verificació
        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId))
                .verifyComplete();

        // Verifiquem que s’han cridat tots els passos
        verify(issuerFactory).createDetailedIssuer(procedureId, LABEL_CREDENTIAL);
        verify(labelCredentialFactory).mapIssuerAndSigner(procedureId, detailedIssuer);
        verify(credentialProcedureService).updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC);
        verify(credentialSignerWorkflow).signAndUpdateCredentialByProcedureId(authorizationHeader, procedureId, JWT_VC);
        verify(credentialProcedureService).updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
        verify(deferredCredentialMetadataService).getResponseUriByProcedureId(procedureId);
        verify(m2mTokenService).getM2MToken();
        verify(credentialDeliveryService).sendVcToResponseUri(
                "https://callback.example.com", "signedVc", "prod-123", "foo@bar.com", "access-token");
    }

    @Test
    void testRetrySignUnsignedCredential_VerifiableCertification_MissingResponseUri() {
        // Preparació del credentialProcedure
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn(VERIFIABLE_CERTIFICATION_CREDENTIAL_TYPE);
        // (Hem eliminat el stub de getCredentialDecoded perquè no s'utilitza aquí)
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        // Simulem el mapping fins a decoded-update
        doReturn(Mono.just(detailedIssuer))
                .when(issuerFactory)
                .createDetailedIssuer(eq(procedureId), anyString());
        when(labelCredentialFactory.mapIssuerAndSigner(procedureId, detailedIssuer))
                .thenReturn(Mono.just("bindedVc"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC))
                .thenReturn(Mono.empty());

        // Simulem la signatura JADES i l'update de l'estat
        doReturn(Mono.just("signedVc"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(authorizationHeader, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(credentialProcedure));

        // Ara provoquem el cas d'error de falta de responseUri
        when(deferredCredentialMetadataService.getResponseUriByProcedureId(procedureId))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId)
                )
                .expectErrorMessage("Missing responseUri for procedureId: " + procedureId)
                .verify();
    }


    @Test
    void testRetrySignUnsignedCredential_DefaultCase_ThrowsIllegalArgument() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn("UNKNOWN_TYPE");
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId))
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalArgumentException &&
                                throwable.getMessage().contains("Unsupported credential type: UNKNOWN_TYPE")
                )
                .verify();
    }

}