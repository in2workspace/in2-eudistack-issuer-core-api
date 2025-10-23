package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.NoCredentialFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialProcedureServiceImplTest {

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @InjectMocks
    private CredentialProcedureServiceImpl credentialProcedureService;

    @Mock
    private ObjectMapper objectMapper;

    @Test
    void createCredentialProcedure_shouldSaveProcedureAndReturnProcedureId() {
        // Given
        String credentialDecoded = "{\"vc\":{\"type\":[\"VerifiableCredential\"]}}";
        String organizationIdentifier = "org-123";
        String expectedProcedureId = UUID.randomUUID().toString();
        String expectedCredentialType = "LEAR_CREDENTIAL_EMPLOYEE";
        String expectedSubject = "TestSubject";
        Timestamp expectedValidUntil = new Timestamp(Instant.now().toEpochMilli() + 1000);

        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .organizationIdentifier(organizationIdentifier)
                .credentialDecoded(credentialDecoded)
                .subject(expectedSubject)
                .credentialType(CredentialType.LEAR_CREDENTIAL_EMPLOYEE)
                .validUntil(expectedValidUntil)
                .build();

        CredentialProcedure savedCredentialProcedure = CredentialProcedure.builder()
                .procedureId(UUID.fromString(expectedProcedureId))
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDecoded(credentialDecoded)
                .organizationIdentifier(organizationIdentifier)
                .credentialType(expectedCredentialType)
                .subject(expectedSubject)
                .updatedAt(new Timestamp(Instant.now().toEpochMilli()))
                .validUntil(expectedValidUntil)
                .build();

        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(savedCredentialProcedure));

        // When
        Mono<String> result = credentialProcedureService.createCredentialProcedure(request);

        // Then
        StepVerifier.create(result)
                .expectNext(expectedProcedureId)
                .verifyComplete();
    }

    @Test
    void getCredentialTypeByProcedureId_shouldReturnNonDefaultType() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String credentialDecoded = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"TestType\"]}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(credentialDecoded);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = credentialProcedureService.getCredentialTypeByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNext("TestType")
                .verifyComplete();
    }

    @Test
    void getCredentialTypeByProcedureId_shouldReturnEmptyIfOnlyDefaultTypesPresent() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String credentialDecoded = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"VerifiableAttestation\"]}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(credentialDecoded);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = credentialProcedureService.getCredentialTypeByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNextCount(0)
                .verifyComplete();
    }

    @Test
    void getCredentialTypeByProcedureId_shouldReturnErrorIfTypeMissing() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String credentialDecoded = "{\"vc\":{}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(credentialDecoded);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = credentialProcedureService.getCredentialTypeByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                        throwable.getMessage().equals("The credential type is missing"))
                .verify();
    }

    @Test
    void getCredentialTypeByProcedureId_shouldReturnErrorIfJsonProcessingExceptionOccurs() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String invalidCredentialDecoded = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"TestType\"}"; // Invalid JSON

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(invalidCredentialDecoded);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        // Simulate any JsonProcessingException (service maps it to ParseCredentialJsonException internally elsewhere; here we only test propagation path)
        when(objectMapper.readTree(invalidCredentialDecoded))
                .thenThrow(new RuntimeException("Invalid JSON"));

        // When
        Mono<String> result = credentialProcedureService.getCredentialTypeByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(RuntimeException.class::isInstance)
                .verify();
    }

    @Test
    void updateDecodedCredentialByProcedureId_shouldUpdateAndSaveCredentialProcedure() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String newCredential = "{\"vc\":{\"type\":[\"NewCredentialType\"]}}";
        String newFormat = "json";

        CredentialProcedure existingCredentialProcedure = new CredentialProcedure();
        existingCredentialProcedure.setProcedureId(UUID.fromString(procedureId));
        existingCredentialProcedure.setCredentialDecoded("{\"vc\":{\"type\":[\"OldCredentialType\"]}}");
        existingCredentialProcedure.setCredentialStatus(CredentialStatusEnum.DRAFT);
        existingCredentialProcedure.setCredentialFormat("old_format");
        existingCredentialProcedure.setUpdatedAt(new Timestamp(Instant.now().toEpochMilli()));

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));

        // When
        Mono<Void> result = credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, newCredential, newFormat);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureRepository, times(1)).findById(UUID.fromString(procedureId));
        verify(credentialProcedureRepository, times(1)).save(existingCredentialProcedure);

        assert existingCredentialProcedure.getCredentialDecoded().equals(newCredential);
        assert existingCredentialProcedure.getCredentialFormat().equals(newFormat);
        assert existingCredentialProcedure.getCredentialStatus() == CredentialStatusEnum.ISSUED;
        assert existingCredentialProcedure.getUpdatedAt().before(new Timestamp(Instant.now().toEpochMilli() + 1000));
    }

    @Test
    void updateDecodedCredentialByProcedureId_shouldHandleProcedureNotFound() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String newCredential = "{\"vc\":{\"type\":[\"NewCredentialType\"]}}";
        String newFormat = "json";

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, newCredential, newFormat);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureRepository, times(1)).findById(UUID.fromString(procedureId));
        verify(credentialProcedureRepository, times(0)).save(any(CredentialProcedure.class));
    }

    @Test
    void getDecodedCredentialByProcedureId_shouldReturnDecodedCredential() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String expectedDecodedCredential = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(expectedDecodedCredential);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));

        // When
        Mono<String> result = credentialProcedureService.getDecodedCredentialByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNext(expectedDecodedCredential)
                .verifyComplete();
    }

    @Test
    void getCredentialStatusByProcedureId_shouldReturnCredentialStatus() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        CredentialStatusEnum expectedStatus = CredentialStatusEnum.ISSUED;

        when(credentialProcedureRepository.findCredentialStatusByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(expectedStatus.name()));

        // When
        Mono<String> result = credentialProcedureService.getCredentialStatusByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNext(expectedStatus.name())
                .verifyComplete();
    }

    @Test
    void getSignerEmailFromDecodedCredentialByProcedureId_shouldReturnMandatorEmail() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String expectedEmail = "mandator@example.com";
        String credentialDecoded = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"signer\":{\"emailAddress\":\"" + expectedEmail + "\"}}}}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(credentialDecoded);
        credentialProcedure.setCredentialType("LEAR_CREDENTIAL_EMPLOYEE");

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);

        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = credentialProcedureService.getSignerEmailFromDecodedCredentialByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNext(expectedEmail)
                .verifyComplete();
    }

    @Test
    void getAllIssuedCredentialByOrganizationIdentifier_shouldReturnAllIssuedCredentials() {
        // Given
        String organizationIdentifier = "org-123";
        String credential1Decoded = "{\"vc\":{\"type\":[\"TestCredentialType1\"]}}";
        String credential2Decoded = "{\"vc\":{\"type\":[\"TestCredentialType2\"]}}";

        CredentialProcedure credentialProcedure1 = new CredentialProcedure();
        credentialProcedure1.setCredentialDecoded(credential1Decoded);
        credentialProcedure1.setCredentialStatus(CredentialStatusEnum.ISSUED);
        credentialProcedure1.setOrganizationIdentifier(organizationIdentifier);

        CredentialProcedure credentialProcedure2 = new CredentialProcedure();
        credentialProcedure2.setCredentialDecoded(credential2Decoded);
        credentialProcedure2.setCredentialStatus(CredentialStatusEnum.ISSUED);
        credentialProcedure2.setOrganizationIdentifier(organizationIdentifier);

        when(credentialProcedureRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.fromIterable(List.of(credentialProcedure1, credentialProcedure2)));

        // When
        StepVerifier.create(credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier))
                .expectNext(credential1Decoded)
                .expectNext(credential2Decoded)
                .verifyComplete();
    }

    @Test
    void getAllIssuedCredentialByOrganizationIdentifier_shouldHandleNoIssuedCredentialsFound() {
        // Given
        String organizationIdentifier = "org-456";

        when(credentialProcedureRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.empty());

        // When / Then
        StepVerifier.create(credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier))
                .expectNextCount(0)
                .verifyComplete();
    }

    // ---------- UPDATED / NEW TESTS FOR getProcedureDetailByProcedureIdAndOrganizationId ----------

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldReturnCredentialDetails_forRegularOrg() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";
        String credentialDecoded = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";
        UUID expectedProcedureId = UUID.fromString(procedureId);
        CredentialStatusEnum status = CredentialStatusEnum.ISSUED;
        String operationMode = "remote";
        String signatureMode = "remote";
        String ownerEmail = "owner@example.com";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(expectedProcedureId);
        credentialProcedure.setCredentialDecoded(credentialDecoded);
        credentialProcedure.setCredentialStatus(status);
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);
        credentialProcedure.setOperationMode(operationMode);
        credentialProcedure.setSignatureMode(signatureMode);
        credentialProcedure.setOwnerEmail(ownerEmail);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);

        when(credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(any(UUID.class), any(String.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded)).thenReturn(credentialNode);

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(details ->
                        details.procedureId().equals(expectedProcedureId) &&
                                details.lifeCycleStatus().equals(status.name()) &&
                                details.credential().equals(credentialNode) &&
                                operationMode.equals(details.operationMode()) &&
                                signatureMode.equals(details.signatureMode()) &&
                                ownerEmail.equals(details.ownerEmail())
                )
                .verifyComplete();

        // Verify correct repo path used
        verify(credentialProcedureRepository, times(1))
                .findByProcedureIdAndOrganizationIdentifier(UUID.fromString(procedureId), organizationIdentifier);
        verify(credentialProcedureRepository, never()).findByProcedureId(any(UUID.class));
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldReturnCredentialDetails_forAdminOrg() throws Exception {
        // Given (admin organization bypass)
        String procedureId = UUID.randomUUID().toString();
        String credentialDecoded = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";
        UUID expectedProcedureId = UUID.fromString(procedureId);
        String operationMode = "remote";
        String signatureMode = "remote";
        String ownerEmail = "admin-owner@example.com";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(expectedProcedureId);
        credentialProcedure.setCredentialDecoded(credentialDecoded);
        credentialProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        credentialProcedure.setOrganizationIdentifier("any-org");
        credentialProcedure.setOperationMode(operationMode);
        credentialProcedure.setSignatureMode(signatureMode);
        credentialProcedure.setOwnerEmail(ownerEmail);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);

        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded)).thenReturn(credentialNode);

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(IN2_ORGANIZATION_IDENTIFIER, procedureId);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(details ->
                        details.procedureId().equals(expectedProcedureId) &&
                                details.credential().equals(credentialNode) &&
                                operationMode.equals(details.operationMode()) &&
                                signatureMode.equals(details.signatureMode()) &&
                                ownerEmail.equals(details.ownerEmail())
                )
                .verifyComplete();

        // Verify admin path used
        verify(credentialProcedureRepository, times(1)).findByProcedureId(UUID.fromString(procedureId));
        verify(credentialProcedureRepository, never())
                .findByProcedureIdAndOrganizationIdentifier(any(UUID.class), anyString());
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldErrorWhenNotFound_forRegularOrg() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";

        when(credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(any(UUID.class), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId);

        // Then
        StepVerifier.create(result)
                .expectErrorSatisfies(err -> {
                    assert err instanceof NoCredentialFoundException;
                    assert err.getMessage().contains(procedureId);
                })
                .verify();
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldErrorWhenNotFound_forAdminOrg() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = IN2_ORGANIZATION_IDENTIFIER;

        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.empty());

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId);

        // Then
        StepVerifier.create(result)
                .expectError(NoCredentialFoundException.class)
                .verify();
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldHandleJsonProcessingException() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";
        String invalidCredentialDecoded = "{\"vc\":{\"type\":[\"TestCredentialType\"}"; // Malformed JSON

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(invalidCredentialDecoded);
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);

        when(credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(any(UUID.class), any(String.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(invalidCredentialDecoded))
                .thenThrow(new JsonParseException(null, "Error parsing credential"));

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(JsonParseException.class::isInstance)
                .verify();
    }
}
