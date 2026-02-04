package es.in2.issuer.backend.statuslist.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.statuslist.domain.service.LegacyCredentialStatusRevocationService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.statuslist.application.policies.StatusListPdpService;
import es.in2.issuer.backend.statuslist.domain.exception.CredentialDecodedInvalidJsonException;
import es.in2.issuer.backend.statuslist.domain.exception.CredentialStatusMissingException;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RevocationWorkflowTest {

    @Mock
    private StatusListProvider statusListProvider;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private StatusListPdpService statusListPdpService;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private EmailService emailService;

    @Mock
    private LegacyCredentialStatusRevocationService legacyCredentialStatusRevocationService;

    @InjectMocks
    private RevocationWorkflow revocationWorkflow;

    private static final String PROCESS_ID = "process-123";
    private static final String BEARER_TOKEN = "Bearer token123";
    private static final String CLEAN_TOKEN = "token123";
    private static final String PROCEDURE_ID = "procedure-456";
    private static final int LIST_ID = 1;

    private CredentialProcedure mockProcedure;

    @BeforeEach
    void setUp() {
        mockProcedure = new CredentialProcedure();
        mockProcedure.setCredentialDecoded(createValidCredentialJson());
    }

    // ========== Test revoke() method ==========

    @Test
    void revoke_WithBitstringType_ShouldSucceed() throws JsonProcessingException {
        // Arrange
        String credentialJson = createValidCredentialJsonWithBitstring();
        mockProcedure.setCredentialDecoded(credentialJson);

        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure)).thenReturn(Mono.empty());
        when(statusListProvider.revoke(PROCEDURE_ID, CLEAN_TOKEN)).thenReturn(Mono.empty());
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(mockProcedure)).thenReturn(Mono.empty());
        when(emailService.notifyIfCredentialStatusChanges(eq(mockProcedure), anyString())).thenReturn(Mono.empty());

        setupObjectMapperForBitstring();

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .verifyComplete();

        verify(statusListProvider).revoke(PROCEDURE_ID, CLEAN_TOKEN);
        verify(legacyCredentialStatusRevocationService, never()).revoke(anyInt(), any());
    }

    @Test
    void revoke_WithLegacyType_ShouldUseLegacyService() throws JsonProcessingException {
        // Arrange
        String credentialJson = createValidCredentialJsonWithLegacyType();
        mockProcedure.setCredentialDecoded(credentialJson);

        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure)).thenReturn(Mono.empty());
        when(legacyCredentialStatusRevocationService.revoke(eq(LIST_ID), any(CredentialStatus.class))).thenReturn(Mono.empty());
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(mockProcedure)).thenReturn(Mono.empty());
        when(emailService.notifyIfCredentialStatusChanges(eq(mockProcedure), anyString())).thenReturn(Mono.empty());

        setupObjectMapperForLegacy();

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .verifyComplete();

        verify(legacyCredentialStatusRevocationService).revoke(eq(LIST_ID), any(CredentialStatus.class));
        verify(statusListProvider, never()).revoke(anyString(), anyString());
    }

    @Test
    void revoke_WithNullCredentialStatus_ShouldUseLegacyService() throws JsonProcessingException {
        // Arrange
        String credentialJson = "{\"vc\": {}}";
        mockProcedure.setCredentialDecoded(credentialJson);

        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure)).thenReturn(Mono.empty());

        JsonNode mockRoot = mock(JsonNode.class);
        when(objectMapper.readTree(credentialJson)).thenReturn(mockRoot);
        when(mockRoot.get("credentialStatus")).thenReturn(null);

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .expectError(CredentialStatusMissingException.class)
                .verify();
    }

    @Test
    void revoke_WithInvalidJson_ShouldThrowException() throws JsonProcessingException {
        // Arrange
        String invalidJson = "{invalid json}";
        mockProcedure.setCredentialDecoded(invalidJson);

        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure)).thenReturn(Mono.empty());
        when(objectMapper.readTree(invalidJson)).thenThrow(new JsonProcessingException("Invalid JSON") {});

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .expectError(CredentialDecodedInvalidJsonException.class)
                .verify();
    }

    @Test
    void revoke_WithNullProcessId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(null, BEARER_TOKEN, PROCEDURE_ID, LIST_ID)
        );
    }

    @Test
    void revoke_WithNullBearerToken_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(PROCESS_ID, null, PROCEDURE_ID, LIST_ID)
        );
    }

    @Test
    void revoke_WithNullProcedureId_ShouldThrowException() {
        assertThrows(
                NullPointerException.class,
                () -> revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, null, LIST_ID)
        );
    }

    @Test
    void revoke_WithValidationFailure_ShouldPropagateError() {
        // Arrange
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure))
                .thenReturn(Mono.error(new RuntimeException("Validation failed")));

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .expectError(RuntimeException.class)
                .verify();
    }

    // ========== Test revokeSystem() method ==========

    @Test
    void revokeSystem_WithBitstringType_ShouldSucceed() throws JsonProcessingException {
        // Arrange
        String credentialJson = createValidCredentialJsonWithBitstring();
        mockProcedure.setCredentialDecoded(credentialJson);

        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredentialSystem(PROCESS_ID, mockProcedure)).thenReturn(Mono.empty());
        when(statusListProvider.revoke(PROCEDURE_ID, CLEAN_TOKEN)).thenReturn(Mono.empty());
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(mockProcedure)).thenReturn(Mono.empty());
        when(emailService.notifyIfCredentialStatusChanges(eq(mockProcedure), anyString())).thenReturn(Mono.empty());

        setupObjectMapperForBitstring();

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .verifyComplete();

        verify(statusListPdpService).validateRevokeCredentialSystem(PROCESS_ID, mockProcedure);
        verify(statusListProvider).revoke(PROCEDURE_ID, CLEAN_TOKEN);
    }

    @Test
    void revokeSystem_WithLegacyType_ShouldUseLegacyService() throws JsonProcessingException {
        // Arrange
        String credentialJson = createValidCredentialJsonWithLegacyType();
        mockProcedure.setCredentialDecoded(credentialJson);

        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredentialSystem(PROCESS_ID, mockProcedure)).thenReturn(Mono.empty());
        when(legacyCredentialStatusRevocationService.revoke(eq(LIST_ID), any(CredentialStatus.class))).thenReturn(Mono.empty());
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(mockProcedure)).thenReturn(Mono.empty());
        when(emailService.notifyIfCredentialStatusChanges(eq(mockProcedure), anyString())).thenReturn(Mono.empty());

        setupObjectMapperForLegacy();

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .verifyComplete();

        verify(legacyCredentialStatusRevocationService).revoke(eq(LIST_ID), any(CredentialStatus.class));
    }

    @Test
    void revokeSystem_WithValidationFailure_ShouldPropagateError() {
        // Arrange
        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredentialSystem(PROCESS_ID, mockProcedure))
                .thenReturn(Mono.error(new RuntimeException("System validation failed")));

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revokeSystem(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .expectError(RuntimeException.class)
                .verify();
    }

    // ========== Test edge cases for parseCredentialStatus ==========

    @Test
    void revoke_WithNullCredentialStatusNode_ShouldThrowException() throws JsonProcessingException {
        // Arrange
        mockProcedure.setCredentialDecoded("{}");

        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure)).thenReturn(Mono.empty());

        JsonNode mockRoot = mock(JsonNode.class);
        JsonNode mockNullNode = mock(JsonNode.class);
        when(objectMapper.readTree(anyString())).thenReturn(mockRoot);
        when(mockRoot.get("credentialStatus")).thenReturn(mockNullNode);
        when(mockNullNode.isNull()).thenReturn(true);

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .expectError(CredentialStatusMissingException.class)
                .verify();
    }

    @Test
    void revoke_WithPartialCredentialStatus_ShouldHandleNullFields() throws JsonProcessingException {
        // Arrange
        String credentialJson = createCredentialJsonWithPartialStatus();
        mockProcedure.setCredentialDecoded(credentialJson);

        when(accessTokenService.getCleanBearerToken(BEARER_TOKEN)).thenReturn(Mono.just(CLEAN_TOKEN));
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(mockProcedure));
        when(statusListPdpService.validateRevokeCredential(PROCESS_ID, CLEAN_TOKEN, mockProcedure)).thenReturn(Mono.empty());
        when(legacyCredentialStatusRevocationService.revoke(eq(LIST_ID), any(CredentialStatus.class))).thenReturn(Mono.empty());
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(mockProcedure)).thenReturn(Mono.empty());
        when(emailService.notifyIfCredentialStatusChanges(eq(mockProcedure), anyString())).thenReturn(Mono.empty());

        setupObjectMapperForPartialStatus();

        // Act & Assert
        StepVerifier.create(revocationWorkflow.revoke(PROCESS_ID, BEARER_TOKEN, PROCEDURE_ID, LIST_ID))
                .verifyComplete();
    }

    // ========== Helper methods ==========

    private String createValidCredentialJson() {
        return """
                {
                    "credentialStatus": {
                        "id": "status-id",
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "revocation",
                        "statusListIndex": "123",
                        "statusListCredential": "credential-id"
                    }
                }
                """;
    }

    private String createValidCredentialJsonWithBitstring() {
        return """
                {
                    "credentialStatus": {
                        "id": "status-id",
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "revocation",
                        "statusListIndex": "123",
                        "statusListCredential": "credential-id"
                    }
                }
                """;
    }

    private String createValidCredentialJsonWithLegacyType() {
        return """
                {
                    "credentialStatus": {
                        "id": "status-id",
                        "type": "StatusList2021Entry",
                        "statusPurpose": "revocation",
                        "statusListIndex": "123",
                        "statusListCredential": "credential-id"
                    }
                }
                """;
    }

    private String createCredentialJsonWithPartialStatus() {
        return """
                {
                    "credentialStatus": {
                        "type": "SomeOtherType"
                    }
                }
                """;
    }

    private void setupObjectMapperForBitstring() throws JsonProcessingException {
        JsonNode mockRoot = mock(JsonNode.class);
        JsonNode mockCredentialStatus = mock(JsonNode.class);
        JsonNode mockId = mock(JsonNode.class);
        JsonNode mockType = mock(JsonNode.class);
        JsonNode mockPurpose = mock(JsonNode.class);
        JsonNode mockIndex = mock(JsonNode.class);
        JsonNode mockCredential = mock(JsonNode.class);

        when(objectMapper.readTree(anyString())).thenReturn(mockRoot);
        when(mockRoot.get("credentialStatus")).thenReturn(mockCredentialStatus);
        when(mockCredentialStatus.isNull()).thenReturn(false);

        when(mockCredentialStatus.get("id")).thenReturn(mockId);
        when(mockCredentialStatus.get("type")).thenReturn(mockType);
        when(mockCredentialStatus.get("statusPurpose")).thenReturn(mockPurpose);
        when(mockCredentialStatus.get("statusListIndex")).thenReturn(mockIndex);
        when(mockCredentialStatus.get("statusListCredential")).thenReturn(mockCredential);

        when(mockId.isNull()).thenReturn(false);
        when(mockType.isNull()).thenReturn(false);
        when(mockPurpose.isNull()).thenReturn(false);
        when(mockIndex.isNull()).thenReturn(false);
        when(mockCredential.isNull()).thenReturn(false);

        when(mockId.asText()).thenReturn("status-id");
        when(mockType.asText()).thenReturn("BitstringStatusListEntry");
        when(mockPurpose.asText()).thenReturn("revocation");
        when(mockIndex.asText()).thenReturn("123");
        when(mockCredential.asText()).thenReturn("credential-id");
    }

    private void setupObjectMapperForLegacy() throws JsonProcessingException {
        JsonNode mockRoot = mock(JsonNode.class);
        JsonNode mockCredentialStatus = mock(JsonNode.class);
        JsonNode mockId = mock(JsonNode.class);
        JsonNode mockType = mock(JsonNode.class);
        JsonNode mockPurpose = mock(JsonNode.class);
        JsonNode mockIndex = mock(JsonNode.class);
        JsonNode mockCredential = mock(JsonNode.class);

        when(objectMapper.readTree(anyString())).thenReturn(mockRoot);
        when(mockRoot.get("credentialStatus")).thenReturn(mockCredentialStatus);
        when(mockCredentialStatus.isNull()).thenReturn(false);

        when(mockCredentialStatus.get("id")).thenReturn(mockId);
        when(mockCredentialStatus.get("type")).thenReturn(mockType);
        when(mockCredentialStatus.get("statusPurpose")).thenReturn(mockPurpose);
        when(mockCredentialStatus.get("statusListIndex")).thenReturn(mockIndex);
        when(mockCredentialStatus.get("statusListCredential")).thenReturn(mockCredential);

        when(mockId.isNull()).thenReturn(false);
        when(mockType.isNull()).thenReturn(false);
        when(mockPurpose.isNull()).thenReturn(false);
        when(mockIndex.isNull()).thenReturn(false);
        when(mockCredential.isNull()).thenReturn(false);

        when(mockId.asText()).thenReturn("status-id");
        when(mockType.asText()).thenReturn("StatusList2021Entry");
        when(mockPurpose.asText()).thenReturn("revocation");
        when(mockIndex.asText()).thenReturn("123");
        when(mockCredential.asText()).thenReturn("credential-id");
    }

    private void setupObjectMapperForPartialStatus() throws JsonProcessingException {
        JsonNode mockRoot = mock(JsonNode.class);
        JsonNode mockCredentialStatus = mock(JsonNode.class);
        JsonNode mockType = mock(JsonNode.class);

        when(objectMapper.readTree(anyString())).thenReturn(mockRoot);
        when(mockRoot.get("credentialStatus")).thenReturn(mockCredentialStatus);
        when(mockCredentialStatus.isNull()).thenReturn(false);

        when(mockCredentialStatus.get("id")).thenReturn(null);
        when(mockCredentialStatus.get("type")).thenReturn(mockType);
        when(mockCredentialStatus.get("statusPurpose")).thenReturn(null);
        when(mockCredentialStatus.get("statusListIndex")).thenReturn(null);
        when(mockCredentialStatus.get("statusListCredential")).thenReturn(null);

        when(mockType.isNull()).thenReturn(false);
        when(mockType.asText()).thenReturn("SomeOtherType");
    }
}
