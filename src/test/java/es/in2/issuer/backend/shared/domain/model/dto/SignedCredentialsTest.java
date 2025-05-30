package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignedCredentialsTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        SignedCredentials.SignedCredential sampleCredential = new SignedCredentials.SignedCredential("sampleCredential");
        List<SignedCredentials.SignedCredential> signedCredentialList = List.of(sampleCredential);

        // Act
        SignedCredentials signedCredentials = new SignedCredentials(signedCredentialList);

        // Assert
        assertEquals(signedCredentialList, signedCredentials.credentials());
    }

    @Test
    void testSetters() {
        // Arrange
        SignedCredentials.SignedCredential sampleCredential = new SignedCredentials.SignedCredential("newSampleCredential");
        List<SignedCredentials.SignedCredential> signedCredentialList = List.of(sampleCredential);

        // Act
        SignedCredentials signedCredentials = SignedCredentials.builder()
                .credentials(signedCredentialList)
                .build();

        // Assert
        assertEquals(signedCredentialList, signedCredentials.credentials());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        SignedCredentials.SignedCredential sampleCredential = new SignedCredentials.SignedCredential("sampleCredential");
        List<SignedCredentials.SignedCredential> signedCredentialList = List.of(sampleCredential);

        SignedCredentials signedCredentials1 = new SignedCredentials(signedCredentialList);
        SignedCredentials signedCredentials2 = new SignedCredentials(signedCredentialList);

        // Assert
        assertEquals(signedCredentials1, signedCredentials2);
        assertEquals(signedCredentials1.hashCode(), signedCredentials2.hashCode());
    }
}