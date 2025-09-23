package es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.Issuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LifeSpan;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Signer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LEARCredentialEmployeeTest {

    @Mock
    private Issuer issuer;

    @Test
    void testBuilderAndGettersUsingMockIssuer() {
        // Build nested objects for the credentialSubject property
        LifeSpan lifeSpan =
                LifeSpan.builder()
                        .startDateTime("2024-01-01T00:00:00Z")
                        .endDateTime("2025-01-01T00:00:00Z")
                        .build();

        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("mandatee-id")
                        .email("mandatee@example.com")
                        .firstName("John")
                        .lastName("Doe")
                        .mobilePhone("+123456789")
                        .build();

        Mandator mandator =
                Mandator.builder()
                        .commonName("MandatorCommonName")
                        .country("US")
                        .email("mandator@example.com")
                        .organization("MandatorOrg")
                        .organizationIdentifier("Org123")
                        .serialNumber("SN123")
                        .build();

        Power power =
                Power.builder()
                        .action("action-value")
                        .domain("domain-value")
                        .function("function-value")
                        .type("type-value")
                        .build();

        Signer signer =
                Signer.builder()
                        .commonName("SignerCommonName")
                        .country("US")
                        .emailAddress("signer@example.com")
                        .organization("SignerOrg")
                        .organizationIdentifier("SignerOrg123")
                        .serialNumber("SignerSN123")
                        .build();

        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .lifeSpan(lifeSpan)
                        .mandatee(mandatee)
                        .mandator(mandator)
                        .power(List.of(power))
                        .signer(signer)
                        .build();

        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        when(issuer.getId()).thenReturn("issuer-mock-id");

        // Build the LEARCredentialEmployee instance using the mock Issuer
        LEARCredentialEmployee employee = LEARCredentialEmployee.builder()
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .id("credential-id")
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .description("Test credential with mock issuer")
                .credentialSubject(credentialSubject)
                .issuer(issuer)
                .validFrom("2024-01-01T00:00:00Z")
                .validUntil("2025-01-01T00:00:00Z")
                .build();

        // Verify that the getters return the expected values
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), employee.context());
        assertEquals("credential-id", employee.id());
        assertEquals(List.of("VerifiableCredential", "LEARCredentialEmployee"), employee.type());
        assertEquals("Test credential with mock issuer", employee.description());
        assertEquals("issuer-mock-id", employee.issuer().getId());
        assertEquals("2024-01-01T00:00:00Z", employee.validFrom());
        assertEquals("2025-01-01T00:00:00Z", employee.validUntil());
        // Verify some nested fields
        assertEquals("John", employee.credentialSubject().mandate().mandatee().firstName());
        assertEquals("MandatorOrg", employee.credentialSubject().mandate().mandator().organization());
        assertEquals("action-value", employee.credentialSubject().mandate().power().get(0).action());
        assertEquals("SignerOrg123", employee.credentialSubject().mandate().signer().organizationIdentifier());
    }

    @Test
    void testEqualsAndHashCodeUsingSameIssuer() {
        // Build nested objects for the credentialSubject property
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .lifeSpan(LifeSpan.builder()
                                .startDateTime("2024-01-01T00:00:00Z")
                                .endDateTime("2025-01-01T00:00:00Z")
                                .build())
                        .mandatee(LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                                .id("mandatee-id")
                                .email("mandatee@example.com")
                                .firstName("John")
                                .lastName("Doe")
                                .mobilePhone("+123456789")
                                .build())
                        .mandator(Mandator.builder()
                                .commonName("MandatorCommonName")
                                .country("US")
                                .email("mandator@example.com")
                                .organization("MandatorOrg")
                                .organizationIdentifier("Org123")
                                .serialNumber("SN123")
                                .build())
                        .power(List.of(Power.builder()
                                .action("action-value")
                                .domain("domain-value")
                                .function("function-value")
                                .type("type-value")
                                .build()))
                        .signer(Signer.builder()
                                .commonName("SignerCommonName")
                                .country("US")
                                .emailAddress("signer@example.com")
                                .organization("SignerOrg")
                                .organizationIdentifier("SignerOrg123")
                                .serialNumber("SignerSN123")
                                .build())
                        .build();

        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        DetailedIssuer detailedIssuer = DetailedIssuer.builder()
                .id("issuer-id")
                .organizationIdentifier("Org123")
                .organization("IssuerOrg")
                .country("US")
                .commonName("IssuerCommonName")
                .serialNumber("IssuerSN123")
                .build();

        LEARCredentialEmployee employee1 = LEARCredentialEmployee.builder()
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .id("credential-id")
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .description("Test credential")
                .credentialSubject(credentialSubject)
                .issuer(detailedIssuer)
                .validFrom("2024-01-01T00:00:00Z")
                .validUntil("2025-01-01T00:00:00Z")
                .build();

        LEARCredentialEmployee employee2 = LEARCredentialEmployee.builder()
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .id("credential-id")
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .description("Test credential")
                .credentialSubject(credentialSubject)
                .issuer(detailedIssuer)
                .validFrom("2024-01-01T00:00:00Z")
                .validUntil("2025-01-01T00:00:00Z")
                .build();

        // Using the same mock issuer, the objects should be equal
        assertEquals(employee1, employee2);
        assertEquals(employee1.hashCode(), employee2.hashCode());
    }
}
