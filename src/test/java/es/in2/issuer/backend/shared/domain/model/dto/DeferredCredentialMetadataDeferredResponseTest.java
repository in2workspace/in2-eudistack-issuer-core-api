package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DeferredCredentialMetadataDeferredResponseTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        String expectedId = "id123";
        String expectedProcedureId = "procedure123";
        String expectedTransactionId = "transaction123";
        String expectedVc = "vc123";

        // Act
        DeferredCredentialMetadataDeferredResponse deferredCredentialMetadataDeferredResponse = new DeferredCredentialMetadataDeferredResponse(
                expectedId,
                expectedProcedureId,
                expectedTransactionId,
                expectedVc
        );

        // Assert
        assertEquals(expectedId, deferredCredentialMetadataDeferredResponse.id());
        assertEquals(expectedProcedureId, deferredCredentialMetadataDeferredResponse.procedureId());
        assertEquals(expectedTransactionId, deferredCredentialMetadataDeferredResponse.transactionId());
        assertEquals(expectedVc, deferredCredentialMetadataDeferredResponse.vc());
    }

    @Test
    void testSetters() {
        // Arrange
        String newId = "newId123";
        String newProcedureId = "newProcedure123";
        String newTransactionId = "newTransaction123";
        String newVc = "newVc123";

        // Act
        DeferredCredentialMetadataDeferredResponse deferredCredentialMetadataDeferredResponse = DeferredCredentialMetadataDeferredResponse.builder()
                .id(newId)
                .procedureId(newProcedureId)
                .transactionId(newTransactionId)
                .vc(newVc)
                .build();

        // Assert
        assertEquals(newId, deferredCredentialMetadataDeferredResponse.id());
        assertEquals(newProcedureId, deferredCredentialMetadataDeferredResponse.procedureId());
        assertEquals(newTransactionId, deferredCredentialMetadataDeferredResponse.transactionId());
        assertEquals(newVc, deferredCredentialMetadataDeferredResponse.vc());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        String expectedId = "id123";
        String expectedProcedureId = "procedure123";
        String expectedTransactionId = "transaction123";
        String expectedVc = "vc123";

        DeferredCredentialMetadataDeferredResponse deferredCredentialMetadataDeferredResponse = new DeferredCredentialMetadataDeferredResponse(
                expectedId,
                expectedProcedureId,
                expectedTransactionId,
                expectedVc
        );
        DeferredCredentialMetadataDeferredResponse deferredCredentialMetadataDeferredResponse2 = new DeferredCredentialMetadataDeferredResponse(
                expectedId,
                expectedProcedureId,
                expectedTransactionId,
                expectedVc
        );

        // Assert
        assertEquals(deferredCredentialMetadataDeferredResponse, deferredCredentialMetadataDeferredResponse2);
        assertEquals(deferredCredentialMetadataDeferredResponse.hashCode(), deferredCredentialMetadataDeferredResponse2.hashCode());
    }
}