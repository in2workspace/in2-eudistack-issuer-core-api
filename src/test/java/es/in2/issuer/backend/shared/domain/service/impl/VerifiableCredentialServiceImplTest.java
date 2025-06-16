package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.VerifiableCertificationFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.JWT_VC;
import static es.in2.issuer.backend.shared.domain.util.Constants.VERIFIABLE_CERTIFICATION;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialServiceImplTest {

    private final String processId = "process-id-123";
    private final String preAuthCode = "pre-auth-code-456";
    private final String transactionId = "transaction-id-789";
    private final String deferredResponseId = "deferred-response-id-456";
    private final String procedureId = "procedure-id-321";
    private final String vcValue = "vc-value-123";
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private CredentialFactory credentialFactory;
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private CredentialSignerWorkflow credentialSignerWorkflow;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    @Mock
    private VerifiableCertificationFactory verifiableCertificationFactory;
    @Mock
    private IssuerFactory issuerFactory;
    @InjectMocks
    private VerifiableCredentialServiceImpl verifiableCredentialServiceImpl;

    @Test
    void bindAccessTokenByPreAuthorizedCode_Success() {
        // Arrange: Mock the service to return a Mono.empty()
        String expectedJti = "expected-jti-value";
        when(deferredCredentialMetadataService.updateAuthServerNonceByAuthServerNonce(expectedJti, preAuthCode))
                .thenReturn(Mono.empty());

        // Act: Call the method
        String validAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJleHBlY3RlZC1qdGktdmFsdWUifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        Mono<Void> result = verifiableCredentialServiceImpl.bindAccessTokenByPreAuthorizedCode(processId, validAccessToken, preAuthCode);

        // Assert: Verify the interactions and result
        StepVerifier.create(result)
                .verifyComplete();

        verify(deferredCredentialMetadataService, times(1))
                .updateAuthServerNonceByAuthServerNonce(expectedJti, preAuthCode);
    }

    @Test
    void bindAccessTokenByPreAuthorizedCode_InvalidToken_ThrowsException() {
        // Arrange: Use an invalid JWT token
        String invalidAccessToken = "invalid-token";

        // Act and Assert
        StepVerifier.create(verifiableCredentialServiceImpl.bindAccessTokenByPreAuthorizedCode(
                        processId, invalidAccessToken, preAuthCode))
                .verifyError(RuntimeException.class);

        // Verify that no interaction with deferredCredentialMetadataService happens
        verify(deferredCredentialMetadataService, times(0))
                .updateAuthServerNonceByAuthServerNonce(anyString(), anyString());
    }

    @Test
    void generateDeferredCredentialResponse_WithVcPresent() {
        // Arrange: Create the request and mock response
        DeferredCredentialRequest deferredCredentialRequest = DeferredCredentialRequest.builder()
                .transactionId(transactionId)
                .build();

        DeferredCredentialMetadataDeferredResponse mockResponseWithVc = DeferredCredentialMetadataDeferredResponse.builder()
                .id(deferredResponseId)
                .procedureId(procedureId)
                .transactionId(transactionId)
                .vc(vcValue)
                .build();

        // Mock the service methods
        when(deferredCredentialMetadataService.getVcByTransactionId(transactionId))
                .thenReturn(Mono.just(mockResponseWithVc));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(deferredCredentialMetadataService.deleteDeferredCredentialMetadataById(deferredResponseId))
                .thenReturn(Mono.empty());

        // Act: Call the method
        Mono<VerifiableCredentialResponse> result = verifiableCredentialServiceImpl.generateDeferredCredentialResponse(processId, deferredCredentialRequest);

        // Assert: Verify the result
        StepVerifier.create(result)
                .expectNextMatches(response ->
                        response.credential().equals(vcValue) && response.transactionId() == null)
                .verifyComplete();

        // Verify the interactions
        verify(deferredCredentialMetadataService, times(1))
                .getVcByTransactionId(transactionId);
        verify(credentialProcedureService, times(1))
                .updateCredentialProcedureCredentialStatusToValidByProcedureId((procedureId));
        verify(deferredCredentialMetadataService, times(1))
                .deleteDeferredCredentialMetadataById(deferredResponseId);
    }

    @Test
    void generateDeferredCredentialResponse_WithVcAbsent() {
        // Arrange: Create the request and mock response
        DeferredCredentialRequest deferredCredentialRequest = DeferredCredentialRequest.builder()
                .transactionId(transactionId)
                .build();

        DeferredCredentialMetadataDeferredResponse mockResponseWithoutVc = DeferredCredentialMetadataDeferredResponse.builder()
                .id(deferredResponseId)
                .procedureId(procedureId)
                .transactionId(transactionId)
                .vc(null) // No VC present
                .build();

        // Mock the service methods
        when(deferredCredentialMetadataService.getVcByTransactionId(transactionId))
                .thenReturn(Mono.just(mockResponseWithoutVc));

        // Act: Call the method
        Mono<VerifiableCredentialResponse> result = verifiableCredentialServiceImpl.generateDeferredCredentialResponse(processId, deferredCredentialRequest);

        // Assert: Verify the result
        StepVerifier.create(result)
                .expectNextMatches(response ->
                        response.transactionId().equals(transactionId) && response.credential() == null)
                .verifyComplete();

        // Verify the interactions
        verify(deferredCredentialMetadataService, times(1))
                .getVcByTransactionId(transactionId);
        verify(credentialProcedureService, times(0))
                .updateCredentialProcedureCredentialStatusToValidByProcedureId(anyString());
        verify(deferredCredentialMetadataService, times(0))
                .deleteDeferredCredentialMetadataById(anyString());
    }

    @Test
    void generateVerifiableCertification_Success() {
        // ─── Arrange ─────────────────────────────────────────────────────────
        String token     = "id-token-123";
        String metadataId  = "metadata-id-123";
        String bindVerifiableCertification = "bind-verifiable-certification-data";

        JsonNode mockCredentialJsonNode = mock(JsonNode.class);
        PreSubmittedDataCredentialRequest preSubmittedCredentialRequest = PreSubmittedDataCredentialRequest.builder()
                .payload(mockCredentialJsonNode)
                .operationMode("SYNC")
                .responseUri("https://example.com/response")
                .build();

        CredentialProcedureCreationRequest mockCreationRequest = CredentialProcedureCreationRequest.builder()
                .credentialId("cert-id-123")
                .organizationIdentifier("org-id-123")
                .credentialDecoded("decoded-certification")
                .build();

        when(credentialFactory
                .mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialRequest, token))
                .thenReturn(Mono.just(mockCreationRequest));

        when(credentialProcedureService.createCredentialProcedure(mockCreationRequest))
                .thenReturn(Mono.just(procedureId));

        when(deferredCredentialMetadataService.createDeferredCredentialMetadata(
                procedureId,
                preSubmittedCredentialRequest.operationMode(),
                preSubmittedCredentialRequest.responseUri()))
                .thenReturn(Mono.just(metadataId));

        DetailedIssuer mockIssuer = mock(DetailedIssuer.class);
        when(issuerFactory.createIssuer(
                procedureId,
                VERIFIABLE_CERTIFICATION))
                .thenReturn(Mono.just(mockIssuer));

        when(verifiableCertificationFactory.mapIssuerAndSigner(
                procedureId,
                mockIssuer))
                .thenReturn(Mono.just(bindVerifiableCertification));

        when(credentialProcedureService.updateDecodedCredentialByProcedureId(
                procedureId,
                bindVerifiableCertification,
                JWT_VC))
                .thenReturn(Mono.empty());

        // ─── Act ────────────────────────────────────────────────────────────
        Mono<String> result = verifiableCredentialServiceImpl
                .generateVerifiableCertification(processId, preSubmittedCredentialRequest, token);

        // ─── Assert ─────────────────────────────────────────────────────────
        StepVerifier.create(result)
                .expectNext(procedureId)
                .verifyComplete();

        verify(credentialFactory, times(1))
                .mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialRequest, token);
        verify(credentialProcedureService, times(1))
                .createCredentialProcedure(mockCreationRequest);
        verify(deferredCredentialMetadataService, times(1))
                .createDeferredCredentialMetadata(
                        procedureId,
                        preSubmittedCredentialRequest.operationMode(),
                        preSubmittedCredentialRequest.responseUri());
        verify(issuerFactory, times(1))
                .createIssuer(procedureId, VERIFIABLE_CERTIFICATION);
        verify(verifiableCertificationFactory, times(1))
                .mapIssuerAndSigner(procedureId, mockIssuer);
        verify(credentialProcedureService, times(1))
                .updateDecodedCredentialByProcedureId(procedureId, bindVerifiableCertification, JWT_VC);
    }

    @Test
    void generateVerifiableCertification_ErrorHandling() {
        // Arrange
        String token = "id-token-123";
        JsonNode mockCredentialJsonNode = mock(JsonNode.class);

        PreSubmittedDataCredentialRequest preSubmittedCredentialRequest = PreSubmittedDataCredentialRequest.builder()
                .payload(mockCredentialJsonNode)
                .operationMode("SYNC")
                .responseUri("https://example.com/response")
                .build();

        // Mock the credential factory behavior
        CredentialProcedureCreationRequest mockCreationRequest = CredentialProcedureCreationRequest.builder()
                .credentialId("cert-id-123")
                .organizationIdentifier("org-id-123")
                .credentialDecoded("decoded-certification")
                .build();

        when(credentialFactory.mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialRequest, token))
                .thenReturn(Mono.just(mockCreationRequest));

        // Mock the credential procedure service
        when(credentialProcedureService.createCredentialProcedure(mockCreationRequest))
                .thenReturn(Mono.just(procedureId));

        // Mock the deferred credential metadata service
        String metadataId = "metadata-id-123";
        when(deferredCredentialMetadataService.createDeferredCredentialMetadata(
                procedureId,
                preSubmittedCredentialRequest.operationMode(),
                preSubmittedCredentialRequest.responseUri()))
                .thenReturn(Mono.just(metadataId));

        // Mock the LEAR credential employee factory to throw an error
        RuntimeException mockException = new RuntimeException("Error generating issuer");
        when(issuerFactory.createIssuer(procedureId, VERIFIABLE_CERTIFICATION))
                .thenReturn(Mono.error(mockException));

        // Act
        Mono<String> result = verifiableCredentialServiceImpl.generateVerifiableCertification(
                processId, preSubmittedCredentialRequest, token);

        // Assert
        StepVerifier.create(result)
                .expectNext(procedureId)  // Should still return the procedureId despite the error
                .verifyComplete();

        // Verify interactions
        verify(credentialFactory, times(1))
                .mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialRequest, token);

        verify(credentialProcedureService, times(1))
                .createCredentialProcedure(mockCreationRequest);

        verify(deferredCredentialMetadataService, times(1))
                .createDeferredCredentialMetadata(
                        procedureId,
                        preSubmittedCredentialRequest.operationMode(),
                        preSubmittedCredentialRequest.responseUri());

        verify(issuerFactory, times(1))
                .createIssuer(procedureId, VERIFIABLE_CERTIFICATION);

        // These should not be called due to the error
        verify(verifiableCertificationFactory, never())
                .mapIssuerAndSigner(any(), any());

        verify(credentialProcedureService, never())
                .updateDecodedCredentialByProcedureId(any(), any(), any());
    }

    @Test
    void generateVerifiableCertification_InitialFlowError() {
        // Arrange
        String token = "id-token-123";
        JsonNode mockCredentialJsonNode = mock(JsonNode.class);

        PreSubmittedDataCredentialRequest preSubmittedCredentialRequest = PreSubmittedDataCredentialRequest.builder()
                .payload(mockCredentialJsonNode)
                .operationMode("SYNC")
                .responseUri("https://example.com/response")
                .build();

        // Mock the credential factory to throw an error
        RuntimeException mockException = new RuntimeException("Error mapping credential");
        when(credentialFactory.mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialRequest, token))
                .thenReturn(Mono.error(mockException));

        // Act & Assert
        StepVerifier.create(verifiableCredentialServiceImpl.generateVerifiableCertification(
                        processId, preSubmittedCredentialRequest, token))
                .expectErrorMatches(error -> error instanceof RuntimeException &&
                        "Error mapping credential".equals(error.getMessage()))
                .verify();

        // Verify interactions - none of the subsequent methods should be called
        verify(credentialProcedureService, never())
                .createCredentialProcedure(any());

        verify(deferredCredentialMetadataService, never())
                .createDeferredCredentialMetadata(any(), any(), any());

        verify(issuerFactory, never())
                .createIssuer(any(), any());

        verify(verifiableCertificationFactory, never())
                .mapIssuerAndSigner(any(), any());

        verify(credentialProcedureService, never())
                .updateDecodedCredentialByProcedureId(any(), any(), any());
    }
}