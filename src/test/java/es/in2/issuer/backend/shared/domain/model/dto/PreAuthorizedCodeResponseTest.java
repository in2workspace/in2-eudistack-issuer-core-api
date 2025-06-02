package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PreAuthorizedCodeResponseTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        String preAuthorizedCode = "testCode";
        String expectedPin = "1234";

        // Act
        PreAuthorizedCodeResponse preAuthorizedCodeResponse = new PreAuthorizedCodeResponse(
                preAuthorizedCode,
                expectedPin
        );

        // Assert
        assertEquals(preAuthorizedCode, preAuthorizedCodeResponse.preAuthorizedCode());
        assertEquals(expectedPin, preAuthorizedCodeResponse.txCode());
    }

    @Test
    void testSetters() {
        // Arrange
        String preAuthorizedCode = "testCode";
        String newPin = "5678";

        // Act
        PreAuthorizedCodeResponse preAuthorizedCodeResponse = PreAuthorizedCodeResponse.builder()
                .preAuthorizedCode(preAuthorizedCode)
                .txCode(newPin)
                .build();

        // Assert
        assertEquals(preAuthorizedCode, preAuthorizedCodeResponse.preAuthorizedCode());
        assertEquals(newPin, preAuthorizedCodeResponse.txCode());
    }
}