package es.in2.issuer.backend.shared.domain.model.dto;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialProcedureCreationRequestTest {

//    @Test
//    void testConstructorAndGetters() {
//        // Arrange
//        String expectedCredentialId = "123456";
//        String expectedOrganizationIdentifier = "org123";
//        String expectedCredentialDecoded = "Decoded Credential";
//        CredentialType expectedCredentialType = CredentialType.LEAR_CREDENTIAL_EMPLOYEE;
//        String expectedSubject = "Subject";
//        Timestamp expectedValidUntil = new Timestamp(System.currentTimeMillis());
//        String expectedOperationMode = "S";
//        String expectedSignatureMode = "remote";
//        String expectedEmail = "user@example.com";
//
//        // Act
//        CredentialProcedureCreationRequest request = new CredentialProcedureCreationRequest(
//                expectedOrganizationIdentifier,
//                expectedCredentialDecoded,
//                expectedCredentialType,
//                expectedSubject,
//                expectedValidUntil,
//                expectedOperationMode,
//                expectedSignatureMode,
//                expectedEmail
//        );
//
//        // Assert
//        assertEquals(expectedOrganizationIdentifier, request.organizationIdentifier());
//        assertEquals(expectedCredentialDecoded, request.credentialDecoded());
//    }

    @Test
    void testSetters() {
        // Arrange
        String newCredentialId = "654321";
        String newOrganizationIdentifier = "org654";
        String newCredentialDecoded = "New Decoded Credential";

        // Act
        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()

                .organizationIdentifier(newOrganizationIdentifier)
                .credentialDecoded(newCredentialDecoded)
                .build();

        // Assert
        assertEquals(newOrganizationIdentifier, request.organizationIdentifier());
        assertEquals(newCredentialDecoded, request.credentialDecoded());
    }

//    @Test
//    void lombokGeneratedMethodsTest() {
//        // Arrange
//        String expectedCredentialId = "123456";
//        String expectedOrganizationIdentifier = "org123";
//        String expectedCredentialDecoded = "Decoded Credential";
//        CredentialType expectedCredentialType1 = CredentialType.LEAR_CREDENTIAL_EMPLOYEE;
//        CredentialType expectedCredentialType2 = CredentialType.LABEL_CREDENTIAL;
//        String expectedSubject = "Subject";
//        Timestamp expectedValidUntil = new Timestamp(System.currentTimeMillis());
//        String expectedOperationMode = "S";
//        String expectedSignatureMode = "remote";
//        String expectedEmail1 = "user@example.com";
//        String expectedEmail2 = "user@example2.com";
//
//        CredentialProcedureCreationRequest request1 = new CredentialProcedureCreationRequest(
//                expectedOrganizationIdentifier,
//                expectedCredentialDecoded,
//                expectedCredentialType1,
//                expectedSubject,
//                expectedValidUntil,
//                expectedOperationMode,
//                expectedSignatureMode,
//                expectedEmail1
//        );
//        CredentialProcedureCreationRequest request2 = new CredentialProcedureCreationRequest(
//                expectedOrganizationIdentifier,
//                expectedCredentialDecoded,
//                expectedCredentialType2,
//                expectedSubject,
//                expectedValidUntil,
//                expectedOperationMode,
//                expectedSignatureMode,
//                expectedEmail2
//        );
//
//        // Assert
//        assertEquals(expectedCredentialType1, request1.credentialType());
//        assertEquals(expectedCredentialType2, request2.credentialType());
//    }
}