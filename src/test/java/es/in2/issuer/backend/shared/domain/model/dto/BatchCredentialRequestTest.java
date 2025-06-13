package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BatchCredentialRequestTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        String expectedFormat = "sampleFormat";
        Proofs expectedProof = new Proofs("jwt_vc_json", List.of("sampleJwt"));
        CredentialRequest.CredentialDefinition expectedCredentialDefinition = new CredentialRequest.CredentialDefinition(Set.of("type"));
        List<CredentialRequest> expectedCredentialRequests = List.of(
                new CredentialRequest(expectedFormat, expectedCredentialDefinition, expectedProof),
                new CredentialRequest(expectedFormat, expectedCredentialDefinition, expectedProof)
        );

        // Act
        BatchCredentialRequest batchRequest = new BatchCredentialRequest(expectedCredentialRequests);

        // Assert
        assertEquals(expectedCredentialRequests, batchRequest.credentialRequests());
    }

    @Test
    void testSetters() {
        // Arrange
        String expectedFormat = "sampleFormat";
        Proofs expectedProof = new Proofs("jwt_vc_json", List.of("sampleJwt"));
        CredentialRequest.CredentialDefinition expectedCredentialDefinition = new CredentialRequest.CredentialDefinition(Set.of("type"));
        List<CredentialRequest> newCredentialRequests = List.of(
                new CredentialRequest(expectedFormat, expectedCredentialDefinition, expectedProof),
                new CredentialRequest(expectedFormat, expectedCredentialDefinition, expectedProof)
        );

        // Act
        BatchCredentialRequest batchRequest = BatchCredentialRequest.builder()
                .credentialRequests(newCredentialRequests)
                .build();

        // Assert
        assertEquals(newCredentialRequests, batchRequest.credentialRequests());
    }
}