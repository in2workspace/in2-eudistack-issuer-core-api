package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PendingCredentialsTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        PendingCredentials.CredentialPayload credentialPayload = new PendingCredentials.CredentialPayload("sampleCredential");
        List<PendingCredentials.CredentialPayload> credentialPayloadList = List.of(credentialPayload);

        // Act
        PendingCredentials pendingCredentials = new PendingCredentials(credentialPayloadList);

        // Assert
        assertEquals(credentialPayloadList, pendingCredentials.credentials());
    }

    @Test
    void testSetters() {
        // Arrange
        PendingCredentials.CredentialPayload credentialPayload = new PendingCredentials.CredentialPayload("newSampleCredential");
        List<PendingCredentials.CredentialPayload> credentialPayloadList = List.of(credentialPayload);

        // Act
        PendingCredentials pendingCredentials = PendingCredentials.builder()
                .credentials(credentialPayloadList)
                .build();

        // Assert
        assertEquals(credentialPayloadList, pendingCredentials.credentials());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        PendingCredentials.CredentialPayload credentialPayload = new PendingCredentials.CredentialPayload("sampleCredential");
        List<PendingCredentials.CredentialPayload> credentialPayloadList = List.of(credentialPayload);

        PendingCredentials pendingCredentials1 = new PendingCredentials(credentialPayloadList);
        PendingCredentials pendingCredentials2 = new PendingCredentials(credentialPayloadList);

        // Assert
        assertEquals(pendingCredentials1, pendingCredentials2);
        assertEquals(pendingCredentials1.hashCode(), pendingCredentials2.hashCode());
    }
}