package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProcedureBasicInfoTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        UUID uuid = UUID.randomUUID();
        String expectedSubject = "John Doe";
        String expectedStatus = "In Progress";
        String expectedCredentialType = "LEAR_CREDENTIAL_EMPLOYEE";
        Instant timestamp = Instant.parse("2023-01-01T12:00:00Z");
        String organizationIdentifier = "ORG";

        // Act
        ProcedureBasicInfo procedureBasicInfo = new ProcedureBasicInfo(
                uuid,
                expectedSubject,
                expectedCredentialType,
                expectedStatus,
                timestamp,
                organizationIdentifier
        );

        // Assert
        assertEquals(uuid, procedureBasicInfo.procedureId());
        assertEquals(expectedSubject, procedureBasicInfo.subject());
        assertEquals(expectedStatus, procedureBasicInfo.status());
        assertEquals(timestamp, procedureBasicInfo.updated());
        assertEquals(expectedCredentialType, procedureBasicInfo.credentialType());
    }

    @Test
    void testSetters() {
        // Arrange
        UUID uuid = UUID.randomUUID();
        String newSubject = "Jane Doe";
        String newStatus = "Completed";
        Instant timestamp = Instant.parse("2024-01-01T12:00:00Z");
        String newCredentialType = "VERIFIABLE_CERTIFICATION";
        String orgId = "VATES-AAAAAA";

        // Act
        ProcedureBasicInfo procedureBasicInfo = ProcedureBasicInfo.builder()
                .procedureId(uuid)
                .subject(newSubject)
                .status(newStatus)
                .updated(timestamp)
                .credentialType(newCredentialType)
                .organizationIdentifier(orgId)
                .build();

        // Assert
        assertEquals(uuid, procedureBasicInfo.procedureId());
        assertEquals(newSubject, procedureBasicInfo.subject());
        assertEquals(newStatus, procedureBasicInfo.status());
        assertEquals(timestamp, procedureBasicInfo.updated());
        assertEquals(newCredentialType, procedureBasicInfo.credentialType());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        UUID uuid = UUID.randomUUID();
        String expectedFullName = "John Doe";
        String expectedStatus = "In Progress";
        Instant timestamp = Instant.parse("2023-01-01T12:00:00Z");
        String expectedCredentialType = "LEAR_CREDENTIAL_EMPLOYEE";
        String organizationIdentifier = "VATES-AAAAAA";

        ProcedureBasicInfo procedureBasicInfo1 = new ProcedureBasicInfo(
                uuid,
                expectedFullName,
                expectedCredentialType,
                expectedStatus,
                timestamp,
                organizationIdentifier        );
        ProcedureBasicInfo procedureBasicInfo2 = new ProcedureBasicInfo(
                uuid,
                expectedFullName,
                expectedCredentialType,
                expectedStatus,
                timestamp,
                organizationIdentifier
        );

        // Assert
        assertEquals(procedureBasicInfo1, procedureBasicInfo2);
        assertEquals(procedureBasicInfo1.hashCode(), procedureBasicInfo2.hashCode());
    }
}