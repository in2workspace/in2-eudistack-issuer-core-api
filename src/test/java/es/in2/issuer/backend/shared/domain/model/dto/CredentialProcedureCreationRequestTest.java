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
        assertThat(request)
                .returns("proc-123", CredentialProcedureCreationRequest::procedureId)
                .returns("org-456", CredentialProcedureCreationRequest::organizationIdentifier)
                .returns("decoded-credential", CredentialProcedureCreationRequest::credentialDecoded)
                .returns(CredentialType.LEAR_CREDENTIAL_EMPLOYEE, CredentialProcedureCreationRequest::credentialType)
                .returns("did:example:subject", CredentialProcedureCreationRequest::subject)
                .returns(validUntil, CredentialProcedureCreationRequest::validUntil)
                .returns("ONLINE", CredentialProcedureCreationRequest::operationMode)
                .returns("JWS", CredentialProcedureCreationRequest::signatureMode)
                .returns("roger@example.com", CredentialProcedureCreationRequest::email);
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
                .procedureId("proc-2")
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
        assertThat(a)
                .isEqualTo(b)
                .hasSameHashCodeAs(b)
                .isNotEqualTo(c)
                .isNotEqualTo(null)
                .isNotEqualTo("not-a-request");
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
        assertThat(text)
                .contains("CredentialProcedureCreationRequest")
                .contains("procedureId=proc-123")
                .contains("organizationIdentifier=org-456")
                .contains("email=roger@example.com");
    }

    @Test
    void builderShouldAllowNullsWhenNotProvided() {
        // Arrange
        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-123")
                .build();

        // Assert
        assertThat(request)
                .returns("proc-123", CredentialProcedureCreationRequest::procedureId)
                .returns(null, CredentialProcedureCreationRequest::organizationIdentifier)
                .returns(null, CredentialProcedureCreationRequest::credentialDecoded)
                .returns(null, CredentialProcedureCreationRequest::credentialType)
                .returns(null, CredentialProcedureCreationRequest::subject)
                .returns(null, CredentialProcedureCreationRequest::validUntil)
                .returns(null, CredentialProcedureCreationRequest::operationMode)
                .returns(null, CredentialProcedureCreationRequest::signatureMode)
                .returns(null, CredentialProcedureCreationRequest::email);
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
        assertThat(request.validUntil())
                .isSameAs(validUntil)
                .satisfies(ts -> assertThat(ts.toString()).startsWith("2040-01-01"));

    }
}
