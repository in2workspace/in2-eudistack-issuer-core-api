package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthServerNonceRequestTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        String expectedPreAuthorizedCode = "123456";
        String expectedAccessToken = "token123";

        // Act
        AuthServerNonceRequest request = new AuthServerNonceRequest(
                expectedPreAuthorizedCode,
                expectedAccessToken
        );

        // Assert
        assertEquals(expectedPreAuthorizedCode, request.preAuthorizedCode());
        assertEquals(expectedAccessToken, request.accessToken());
    }

    @Test
    void testSetters() {
        // Arrange
        String newPreAuthorizedCode = "654321";
        String newAccessToken = "token654";

        // Act
        AuthServerNonceRequest request = AuthServerNonceRequest.builder()
                .preAuthorizedCode(newPreAuthorizedCode)
                .accessToken(newAccessToken)
                .build();

        // Assert
        assertEquals(newPreAuthorizedCode, request.preAuthorizedCode());
        assertEquals(newAccessToken, request.accessToken());
    }
}