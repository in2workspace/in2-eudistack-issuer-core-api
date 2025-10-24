package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialProceduresTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        ProcedureBasicInfo procedureBasicInfo = new ProcedureBasicInfo(
                UUID.randomUUID(),
                "John Doe",
                "LEAR_CREDENTIAL_EMPLOYEE",
                "In Progress",
                Instant.parse("2023-01-01 12:00:00"),
                "or"
                );
        CredentialProcedures.CredentialProcedure credentialProcedure = new CredentialProcedures.CredentialProcedure(procedureBasicInfo);
        List<CredentialProcedures.CredentialProcedure> expectedCredentialProcedures = List.of(credentialProcedure);

        // Act
        CredentialProcedures credentialProcedures = new CredentialProcedures(expectedCredentialProcedures);

        // Assert
        assertEquals(expectedCredentialProcedures, credentialProcedures.credentialProcedures());
    }

    @Test
    void testSetters() {
        // Arrange
        ProcedureBasicInfo procedureBasicInfo = new ProcedureBasicInfo(
                UUID.randomUUID(),
                "Jane Doe",
                "LEAR_CREDENTIAL_EMPLOYEE",
                "Completed",
                Instant.parse("2024-01-01 12:00:00"),
                "org"
        );
        CredentialProcedures.CredentialProcedure credentialProcedure = new CredentialProcedures.CredentialProcedure(procedureBasicInfo);
        List<CredentialProcedures.CredentialProcedure> newCredentialProcedures = List.of(credentialProcedure);

        // Act
        CredentialProcedures credentialProcedures = CredentialProcedures.builder()
                .credentialProcedures(newCredentialProcedures)
                .build();

        // Assert
        assertEquals(newCredentialProcedures, credentialProcedures.credentialProcedures());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        ProcedureBasicInfo procedureBasicInfo = new ProcedureBasicInfo(
                UUID.randomUUID(),
                "John Doe",
                "LEAR_CREDENTIAL_EMPLOYEE",
                "In Progress",
                Instant.parse("2023-01-01 12:00:00"),
                "org"
        );
        CredentialProcedures.CredentialProcedure credentialProcedure = new CredentialProcedures.CredentialProcedure(procedureBasicInfo);
        List<CredentialProcedures.CredentialProcedure> expectedCredentialProcedures = List.of(credentialProcedure);

        CredentialProcedures credentialProcedures1 = new CredentialProcedures(expectedCredentialProcedures);
        CredentialProcedures credentialProcedures2 = new CredentialProcedures(expectedCredentialProcedures);

        // Assert
        assertEquals(credentialProcedures1, credentialProcedures2);
        assertEquals(credentialProcedures1.hashCode(), credentialProcedures2.hashCode());
    }
}