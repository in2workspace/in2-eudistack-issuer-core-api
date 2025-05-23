package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DeferredCredentialRequestTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        String expectedTransactionId = "958e84cf-888b-488a-bf30-7f3b14f70699";

        // Act
        DeferredCredentialRequest deferredCredentialRequest = new DeferredCredentialRequest(expectedTransactionId);

        // Assert
        assertEquals(expectedTransactionId, deferredCredentialRequest.transactionId());
    }

    @Test
    void testSetters() {
        // Arrange
        String newTransactionId = "newTransactionId";

        // Act
        DeferredCredentialRequest deferredCredentialRequest = DeferredCredentialRequest.builder()
                .transactionId(newTransactionId)
                .build();

        // Assert
        assertEquals(newTransactionId, deferredCredentialRequest.transactionId());
    }
}