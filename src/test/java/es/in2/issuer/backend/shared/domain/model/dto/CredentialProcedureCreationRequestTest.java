package es.in2.issuer.backend.shared.domain.model.dto;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialProcedureCreationRequestTest {

    @Test
    void builderShouldCreateRecordWithAllFields() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-123")
                .organizationIdentifier("org-456")
                .credentialDecoded("decoded-credential")
                .credentialType(CredentialType.LEAR_CREDENTIAL_EMPLOYEE)
                .subject("did:example:subject")
                .validUntil(validUntil)
                .operationMode("ONLINE")
                .signatureMode("JWS")
                .email("roger@example.com")
                .build();

        // Assert
        assertThat(request.procedureId()).isEqualTo("proc-123");
        assertThat(request.organizationIdentifier()).isEqualTo("org-456");
        assertThat(request.credentialDecoded()).isEqualTo("decoded-credential");
        assertThat(request.credentialType()).isEqualTo(CredentialType.LEAR_CREDENTIAL_EMPLOYEE);
        assertThat(request.subject()).isEqualTo("did:example:subject");
        assertThat(request.validUntil()).isSameAs(validUntil);
        assertThat(request.operationMode()).isEqualTo("ONLINE");
        assertThat(request.signatureMode()).isEqualTo("JWS");
        assertThat(request.email()).isEqualTo("roger@example.com");
    }

    @Test
    void equalsAndHashCodeShouldWorkForSameValues() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        CredentialProcedureCreationRequest a = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-1")
                .organizationIdentifier("org-1")
                .credentialDecoded("cred")
                .credentialType(CredentialType.LABEL_CREDENTIAL)
                .subject("subj")
                .validUntil(validUntil)
                .operationMode("ONLINE")
                .signatureMode("JWS")
                .email("a@b.com")
                .build();

        CredentialProcedureCreationRequest b = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-1")
                .organizationIdentifier("org-1")
                .credentialDecoded("cred")
                .credentialType(CredentialType.LABEL_CREDENTIAL)
                .subject("subj")
                .validUntil(validUntil)
                .operationMode("ONLINE")
                .signatureMode("JWS")
                .email("a@b.com")
                .build();

        CredentialProcedureCreationRequest c = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-2") // Different
                .organizationIdentifier("org-1")
                .credentialDecoded("cred")
                .credentialType(CredentialType.LABEL_CREDENTIAL)
                .subject("subj")
                .validUntil(validUntil)
                .operationMode("ONLINE")
                .signatureMode("JWS")
                .email("a@b.com")
                .build();

        // Assert
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());

        assertThat(a).isNotEqualTo(c);
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("not-a-request");
    }

    @Test
    void toStringShouldContainClassNameAndSomeFields() {
        // Arrange
        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-123")
                .organizationIdentifier("org-456")
                .email("roger@example.com")
                .build();

        // Act
        String text = request.toString();

        // Assert
        assertThat(text).contains("CredentialProcedureCreationRequest");
        assertThat(text).contains("procedureId=proc-123");
        assertThat(text).contains("organizationIdentifier=org-456");
        assertThat(text).contains("email=roger@example.com");
    }

    @Test
    void builderShouldAllowNullsWhenNotProvided() {
        // Arrange
        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-123")
                .build();

        // Assert
        assertThat(request.procedureId()).isEqualTo("proc-123");

        assertThat(request.organizationIdentifier()).isNull();
        assertThat(request.credentialDecoded()).isNull();
        assertThat(request.credentialType()).isNull();
        assertThat(request.subject()).isNull();
        assertThat(request.validUntil()).isNull();
        assertThat(request.operationMode()).isNull();
        assertThat(request.signatureMode()).isNull();
        assertThat(request.email()).isNull();
    }

    @Test
    void credentialTypeShouldExposeTypeId() {
        // Arrange
        CredentialType type = CredentialType.LEAR_CREDENTIAL_MACHINE;

        // Assert
        assertThat(type.getTypeId()).isEqualTo("LEARCredentialMachine");
    }

    @Test
    void timestampIsMutableAndRecordDoesNotDefensivelyCopyIt() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .validUntil(validUntil)
                .build();

        // Act
        validUntil.setTime(Timestamp.valueOf("2040-01-01 00:00:00").getTime());

        // Assert
        assertThat(request.validUntil()).isSameAs(validUntil);
        assertThat(request.validUntil().toString()).startsWith("2040-01-01");
    }
}
