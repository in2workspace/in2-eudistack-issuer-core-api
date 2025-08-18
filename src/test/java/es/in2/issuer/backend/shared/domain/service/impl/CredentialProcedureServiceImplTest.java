package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedures;
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
        String credentialId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";
        String credentialDecoded = "{\"vc\":{\"type\":[\"VerifiableCredential\"]}}";
        String expectedProcedureId = UUID.randomUUID().toString();
        String expectedCredentialType = "LEAR_CREDENTIAL_EMPLOYEE";
        String expectedSubject = "TestSubject";
        Timestamp expectedValidUntil = new Timestamp(Instant.now().toEpochMilli() + 1000);

        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .credentialId(credentialId)
                .organizationIdentifier(organizationIdentifier)
                .credentialDecoded(credentialDecoded)
                .subject(expectedSubject)
                .credentialType(CredentialType.LEAR_CREDENTIAL_EMPLOYEE)
                .validUntil(expectedValidUntil)
                .build();

        CredentialProcedure savedCredentialProcedure = CredentialProcedure.builder()
                .procedureId(UUID.fromString(expectedProcedureId))
                .credentialId(UUID.fromString(credentialId))
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDecoded(credentialDecoded)
                .organizationIdentifier(organizationIdentifier)
                .credentialType(expectedCredentialType)
                .subject(expectedSubject)
                .updatedAt(new Timestamp(Instant.now().toEpochMilli()))
                .validUntil(expectedValidUntil)
                .build();

        // When
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(savedCredentialProcedure));

        // Execute
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

        // When
        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // Execute
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

        // When
        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // Execute
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

        // When
        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // Execute
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

        // When
        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(invalidCredentialDecoded))
                .thenThrow(new RuntimeException("Invalid JSON"));

        // Execute
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

        // When
        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));

        // Execute
        Mono<Void> result = credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, newCredential, newFormat);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).findById(UUID.fromString(procedureId));
        verify(credentialProcedureRepository, times(1)).save(existingCredentialProcedure);

        assert existingCredentialProcedure.getCredentialDecoded().equals(newCredential);
        assert existingCredentialProcedure.getCredentialFormat().equals(newFormat);
        assert existingCredentialProcedure.getCredentialStatus() == CredentialStatusEnum.ISSUED;
        assert existingCredentialProcedure.getUpdatedAt().before(new Timestamp(Instant.now().toEpochMilli() + 1000)); // Ensures the updated timestamp is recent
    }

    @Test
    void updateDecodedCredentialByProcedureId_shouldHandleProcedureNotFound() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String newCredential = "{\"vc\":{\"type\":[\"NewCredentialType\"]}}";
        String newFormat = "json";

        // When
        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.empty());

        // Execute
        Mono<Void> result = credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, newCredential, newFormat);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

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

        // When
        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));

        // Execute
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

        // When
        when(credentialProcedureRepository.findCredentialStatusByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(expectedStatus.name()));

        // Execute
        Mono<String> result = credentialProcedureService.getCredentialStatusByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNext(expectedStatus.name())
                .verifyComplete();
    }

//    @Test
//    void getMandateeEmailFromDecodedCredentialByProcedureId_shouldReturnMandateeEmail() throws Exception {
//        // Given
//        String procedureId = UUID.randomUUID().toString();
//        String expectedEmail = "mandatee@example.com";
//        String credentialDecoded = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandatee\":{\"email\":\"" + expectedEmail + "\"}}}}}";
//
//        CredentialProcedure credentialProcedure = new CredentialProcedure();
//        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
//        credentialProcedure.setCredentialDecoded(credentialDecoded);
//
//        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);
//
//        // When
//        when(credentialProcedureRepository.findById(any(UUID.class)))
//                .thenReturn(Mono.just(credentialProcedure));
//        when(objectMapper.readTree(credentialDecoded))
//                .thenReturn(credentialNode);
//
//        // Execute
//        Mono<String> result = credentialProcedureService.getMandateeEmailFromDecodedCredentialByProcedureId(procedureId);
//
//        // Then
//        StepVerifier.create(result)
//                .expectNext(expectedEmail)
//                .verifyComplete();
//    }

//    @Test
//    void getMandateeFirstNameFromDecodedCredentialByProcedureId_shouldReturnMandateeFirstName() throws Exception {
//        // Given
//        String procedureId = UUID.randomUUID().toString();
//        String expectedFirstName = "John";
//        String credentialDecoded = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandatee\":{\"firstName\":\"" + expectedFirstName + "\"}}}}}";
//
//        CredentialProcedure credentialProcedure = new CredentialProcedure();
//        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
//        credentialProcedure.setCredentialDecoded(credentialDecoded);
//
//        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);
//
//        // When
//        when(credentialProcedureRepository.findById(any(UUID.class)))
//                .thenReturn(Mono.just(credentialProcedure));
//        when(objectMapper.readTree(credentialDecoded))
//                .thenReturn(credentialNode);
//
//        // Execute
//        Mono<String> result = credentialProcedureService.getMandateeFirstNameFromDecodedCredentialByProcedureId(procedureId);
//
//        // Then
//        StepVerifier.create(result)
//                .expectNext(expectedFirstName)
//                .verifyComplete();
//    }
//
//    @Test
//    void getMandateeCompleteNameFromDecodedCredentialByProcedureId_shouldReturnMandateeCompleteName() throws Exception {
//        // Given
//        String procedureId = UUID.randomUUID().toString();
//        String expectedFirstName = "John";
//        String expectedLastName = "Doe";
//        String expectedCompleteName = "John Doe";
//
//        String credentialDecoded = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandatee\":{" +
//                "\"firstName\":\"" + expectedFirstName + "\"," +
//                "\"lastName\":\"" + expectedLastName + "\"" +
//                "}}}}}";
//        CredentialProcedure credentialProcedure = new CredentialProcedure();
//        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
//        credentialProcedure.setCredentialDecoded(credentialDecoded);
//
//        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);
//
//        // When
//        when(credentialProcedureRepository.findById(any(UUID.class)))
//                .thenReturn(Mono.just(credentialProcedure));
//        when(objectMapper.readTree(credentialDecoded))
//                .thenReturn(credentialNode);
//
//        // Execute
//        Mono<String> result = credentialProcedureService.getMandateeCompleteNameFromDecodedCredentialByProcedureId(procedureId);
//
//        // Then
//        StepVerifier.create(result)
//                .expectNext(expectedCompleteName)
//                .verifyComplete();
//    }

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

        // When
        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // Execute
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

        List<CredentialProcedure> issuedCredentials = List.of(credentialProcedure1, credentialProcedure2);

        // When
        when(credentialProcedureRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.fromIterable(issuedCredentials));

        // Execute
        Flux<String> result = credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier);

        // Then
        StepVerifier.create(result)
                .expectNext(credential1Decoded)
                .expectNext(credential2Decoded)
                .verifyComplete();
    }

    @Test
    void getAllIssuedCredentialByOrganizationIdentifier_shouldHandleNoIssuedCredentialsFound() {
        // Given
        String organizationIdentifier = "org-456";

        // When
        when(credentialProcedureRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.empty());

        // Execute
        Flux<String> result = credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier);

        // Then
        StepVerifier.create(result)
                .expectNextCount(0)
                .verifyComplete();
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldReturnCredentialDetails() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";
        String credentialDecoded = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";
        UUID expectedProcedureId = UUID.fromString(procedureId);
        CredentialStatusEnum status = CredentialStatusEnum.ISSUED;

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(expectedProcedureId);
        credentialProcedure.setCredentialDecoded(credentialDecoded);
        credentialProcedure.setCredentialStatus(status);
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);

        // When
        when(credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(any(UUID.class), any(String.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        // Execute
        Mono<CredentialDetails> result = credentialProcedureService.getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(details ->
                        details.procedureId().equals(expectedProcedureId) &&
                                details.lifeCycleStatus().equals(status.name()) &&
                                details.credential().equals(credentialNode))
                .verifyComplete();
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

        // When
        when(credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(any(UUID.class), any(String.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(invalidCredentialDecoded))
                .thenThrow(new JsonParseException(null, "Error parsing credential"));

        // Execute
        Mono<CredentialDetails> result = credentialProcedureService.getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(JsonParseException.class::isInstance)
                .verify();
    }

    @Test
    void updatedEncodedCredentialByCredentialId_shouldUpdateAndReturnProcedureId() {
        // Given
        String credentialId = UUID.randomUUID().toString();
        String newEncodedCredential = "newEncodedCredential";
        UUID procedureId = UUID.randomUUID();

        CredentialProcedure existingCredentialProcedure = new CredentialProcedure();
        existingCredentialProcedure.setProcedureId(procedureId);
        existingCredentialProcedure.setCredentialId(UUID.fromString(credentialId));
        existingCredentialProcedure.setCredentialEncoded("oldEncodedCredential");
        existingCredentialProcedure.setCredentialStatus(CredentialStatusEnum.ISSUED);

        // When
        when(credentialProcedureRepository.findByCredentialId(any(UUID.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));

        // Execute
        Mono<String> result = credentialProcedureService.updatedEncodedCredentialByCredentialId(newEncodedCredential, credentialId);

        // Then
        StepVerifier.create(result)
                .expectNext(procedureId.toString())
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).findByCredentialId(UUID.fromString(credentialId));
        verify(credentialProcedureRepository, times(1)).save(existingCredentialProcedure);

        assert existingCredentialProcedure.getCredentialEncoded().equals(newEncodedCredential);
    }

//    @Test
//    void getMandatorOrganizationFromDecodedCredentialByProcedureId_shouldReturnMandatorOrganization() throws Exception {
//        // Given
//        String procedureId = UUID.randomUUID().toString();
//        String expectedOrganization = "organization";
//        String credentialDecoded = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organization\":\"" + expectedOrganization + "\"}}}}}";
//
//        CredentialProcedure credentialProcedure = new CredentialProcedure();
//        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
//        credentialProcedure.setCredentialDecoded(credentialDecoded);
//
//        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);
//
//        // When
//        when(credentialProcedureRepository.findById(any(UUID.class)))
//                .thenReturn(Mono.just(credentialProcedure));
//        when(objectMapper.readTree(credentialDecoded))
//                .thenReturn(credentialNode);
//
//        // Execute
//        Mono<String> result = credentialProcedureService.getMandatorOrganizationFromDecodedCredentialByProcedureId(procedureId);
//
//        // Then
//        StepVerifier.create(result)
//                .expectNext(expectedOrganization)
//                .verifyComplete();
//    }

    @Test
    void updateCredentialProcedureCredentialStatusToValidByProcedureId_shouldUpdateStatusToValid() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        UUID uuidProcedureId = UUID.fromString(procedureId);

        CredentialProcedure existingCredentialProcedure = new CredentialProcedure();
        existingCredentialProcedure.setProcedureId(uuidProcedureId);
        existingCredentialProcedure.setCredentialStatus(CredentialStatusEnum.ISSUED);

        // When
        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));

        // Execute
        Mono<Void> result = credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).findByProcedureId(uuidProcedureId);
        verify(credentialProcedureRepository, times(1)).save(existingCredentialProcedure);

        assert existingCredentialProcedure.getCredentialStatus() == CredentialStatusEnum.VALID;
    }

    @Test
    void updateCredentialProcedureCredentialStatusToRevoke_shouldUpdateStatusToRevoke() {
        // Given
        String credentialId = UUID.randomUUID().toString();
        UUID uuidCredentialId = UUID.fromString(credentialId);

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setCredentialId(uuidCredentialId);
        credentialProcedure.setCredentialStatus(CredentialStatusEnum.VALID);

        // When
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> {
                    CredentialProcedure saved = invocation.getArgument(0);
                    return Mono.just(saved);
                });
        // Execute
        Mono<Void> result = credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(credentialProcedure);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).save(credentialProcedure);

        assert credentialProcedure.getCredentialStatus() == CredentialStatusEnum.REVOKED;
    }

    @Test
    void getAllProceduresBasicInfoByOrganizationId_shouldReturnBasicInfoForAllProcedures() throws Exception {
        // Given
        String organizationIdentifier = "org-123";
        String credentialDecoded1 = "{\"vc\":{\"type\":[\"LEARCredentialEmployee\",\"VerifiableCredential\"],\"credentialSubject\":{\"mandate\":{\"mandatee\":{\"first_name\":\"John\", \"last_name\":\"Doe\"}}}}}";
        String credentialDecoded2 = "{\"vc\":{\"type\":[\"VerifiableCertification\",\"VerifiableCredential\"],\"credentialSubject\":{\"product\":{\"productName\":\"ProductName\", \"last_name\":\"Smith\"}}}}";

        UUID procedureId1 = UUID.fromString("f1c19a93-b2c4-47b1-be88-18e9b64d1057");
        UUID procedureId2 = UUID.fromString("bc4ea3b1-a90d-4303-976f-62342092bac8");
        Timestamp updated1 = Timestamp.from(Instant.now());
        Timestamp updated2 = Timestamp.from(Instant.now().minusSeconds(3600));

        CredentialProcedure credentialProcedure1 = new CredentialProcedure();
        credentialProcedure1.setProcedureId(procedureId1);
        credentialProcedure1.setCredentialDecoded(credentialDecoded1);
        credentialProcedure1.setCredentialStatus(CredentialStatusEnum.ISSUED);
        credentialProcedure1.setOrganizationIdentifier(organizationIdentifier);
        credentialProcedure1.setUpdatedAt(updated1);
        credentialProcedure1.setCredentialType(CredentialType.LEAR_CREDENTIAL_EMPLOYEE.toString());
        credentialProcedure1.setSubject("John Doe");

        CredentialProcedure credentialProcedure2 = new CredentialProcedure();
        credentialProcedure2.setProcedureId(procedureId2);
        credentialProcedure2.setCredentialDecoded(credentialDecoded2);
        credentialProcedure2.setCredentialStatus(CredentialStatusEnum.DRAFT);
        credentialProcedure2.setOrganizationIdentifier(organizationIdentifier);
        credentialProcedure2.setUpdatedAt(updated2);
        credentialProcedure2.setCredentialType(CredentialType.LABEL_CREDENTIAL.toString());
        credentialProcedure2.setSubject("ProductName");


        List<CredentialProcedure> procedures = List.of(credentialProcedure1, credentialProcedure2);

        JsonNode credentialNode1 = new ObjectMapper().readTree(credentialDecoded1);
        JsonNode credentialNode2 = new ObjectMapper().readTree(credentialDecoded2);

        // When
        when(credentialProcedureRepository.findAllByOrganizationIdentifier(any(String.class)))
                .thenReturn(Flux.fromIterable(procedures));
        when(objectMapper.readTree(credentialDecoded1)).thenReturn(credentialNode1);
        when(objectMapper.readTree(credentialDecoded2)).thenReturn(credentialNode2);

        when(credentialProcedureRepository.findById(UUID.fromString("f1c19a93-b2c4-47b1-be88-18e9b64d1057"))).thenReturn(Mono.just(credentialProcedure1));
        when(credentialProcedureRepository.findById(UUID.fromString("bc4ea3b1-a90d-4303-976f-62342092bac8"))).thenReturn(Mono.just(credentialProcedure2));

        // Execute
        Mono<CredentialProcedures> result = credentialProcedureService.getAllProceduresBasicInfoByOrganizationId(organizationIdentifier);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(credentialProcedures -> {
                    List<CredentialProcedures.CredentialProcedure> credentialProcedureList = credentialProcedures.credentialProcedures();
                    return credentialProcedureList.size() == 2 &&
                            credentialProcedureList.get(0).credentialProcedure().procedureId().equals(procedureId1) &&
                            credentialProcedureList.get(0).credentialProcedure().subject().equals("John Doe") &&
                            credentialProcedureList.get(0).credentialProcedure().status().equals(CredentialStatusEnum.ISSUED.name()) &&
                            credentialProcedureList.get(0).credentialProcedure().updated().equals(updated1) &&
                            credentialProcedureList.get(0).credentialProcedure().credentialType().equals(CredentialType.LEAR_CREDENTIAL_EMPLOYEE.name()) &&
                            credentialProcedureList.get(1).credentialProcedure().procedureId().equals(procedureId2) &&
                            credentialProcedureList.get(1).credentialProcedure().subject().equals("ProductName") &&
                            credentialProcedureList.get(1).credentialProcedure().status().equals(CredentialStatusEnum.DRAFT.name()) &&
                            credentialProcedureList.get(1).credentialProcedure().credentialType().equals(CredentialType.LABEL_CREDENTIAL.name()) &&
                            credentialProcedureList.get(1).credentialProcedure().updated().equals(updated2);
                })
                .verifyComplete();
    }

    @Test
    void updateFormatByProcedureId(){
        // Given
        String procedureId = UUID.randomUUID().toString();
        String newFormat = "new_format";

        CredentialProcedure existingCredentialProcedure = new CredentialProcedure();
        existingCredentialProcedure.setProcedureId(UUID.fromString(procedureId));
        existingCredentialProcedure.setCredentialFormat("old_format");
        existingCredentialProcedure.setUpdatedAt(new Timestamp(Instant.now().toEpochMilli()));

        // When
        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.empty());

        // Execute
        Mono<Void> result = credentialProcedureService.updateFormatByProcedureId(procedureId, newFormat);

        // Then
        StepVerifier.create(result)
                .verifyComplete();
    }

    @Test
    void getEmailCredentialOfferInfoByProcedureId_shouldReturnInfoForLearCredentialMachine() throws Exception {
        String procedureId = UUID.randomUUID().toString();

        String credentialDecoded = """
        {
          "credentialSubject": {
            "mandate": {
              "mandator": {
                "commonName": "Acme Robot 2000",
                "organization": "Acme Corp",
                "email": "robot@acme.test"
              }
            }
          }
        }
        """;

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(credentialDecoded);
        credentialProcedure.setCredentialType("LEAR_CREDENTIAL_MACHINE");

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDecoded);

        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDecoded))
                .thenReturn(credentialNode);

        Mono<CredentialOfferEmailNotificationInfo> result =
                credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(procedureId);

        StepVerifier.create(result)
                .assertNext(info -> {
                    String s = info.toString();
                    assert s.contains("robot@acme.test");
                    assert s.contains("Acme Robot 2000");
                    assert s.contains("Acme Corp");
                })
                .verifyComplete();
    }

    @Test
    void getEmailCredentialOfferInfoByProcedureId_shouldMapJsonErrorForLearCredentialMachine() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String malformedJson = "{ \"credentialSubject\": { \"mandate\": { \"mandator\": { \"email\": ";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDecoded(malformedJson);
        credentialProcedure.setCredentialType("LEAR_CREDENTIAL_MACHINE");

        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));

        when(objectMapper.readTree(malformedJson))
                .thenThrow(new com.fasterxml.jackson.core.JsonParseException(null, "broken json"));

        // Execute
        Mono<CredentialOfferEmailNotificationInfo> result =
                credentialProcedureService.getEmailCredentialOfferInfoByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectError(ParseCredentialJsonException.class)
                .verify();
    }

}