package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BatchCredentialResponseTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        BatchCredentialResponse.CredentialResponse expectedCredentialResponse = new BatchCredentialResponse.CredentialResponse("sampleCredential");
        List<BatchCredentialResponse.CredentialResponse> expectedCredentialResponses = List.of(expectedCredentialResponse);

        // Act
        BatchCredentialResponse batchCredentialResponse = new BatchCredentialResponse(expectedCredentialResponses);

        // Assert
        assertEquals(expectedCredentialResponses, batchCredentialResponse.credentialResponses());
    }

    @Test
    void testSetters() {
        // Arrange
        BatchCredentialResponse.CredentialResponse newCredentialResponse = new BatchCredentialResponse.CredentialResponse("newSampleCredential");
        List<BatchCredentialResponse.CredentialResponse> newCredentialResponses = List.of(newCredentialResponse);

        // Act
        BatchCredentialResponse batchCredentialResponse = BatchCredentialResponse.builder()
                .credentialResponses(newCredentialResponses)
                .build();

        // Assert
        assertEquals(newCredentialResponses, batchCredentialResponse.credentialResponses());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        BatchCredentialResponse.CredentialResponse expectedCredentialResponse = new BatchCredentialResponse.CredentialResponse("sampleCredential");
        List<BatchCredentialResponse.CredentialResponse> expectedCredentialResponses = List.of(expectedCredentialResponse);

        BatchCredentialResponse response1 = new BatchCredentialResponse(expectedCredentialResponses);
        BatchCredentialResponse response2 = new BatchCredentialResponse(expectedCredentialResponses);

        // Assert
        assertEquals(response1, response2);
        assertEquals(response1.hashCode(), response2.hashCode());
    }
}