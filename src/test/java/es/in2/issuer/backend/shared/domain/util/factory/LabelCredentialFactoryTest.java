//package es.in2.issuer.backend.shared.domain.util.factory;
//
//import com.fasterxml.jackson.databind.JsonNode;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.nimbusds.jose.Payload;
//import com.nimbusds.jwt.SignedJWT;
//import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
//import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
//import es.in2.issuer.backend.shared.domain.model.dto.credential.LabelCredential;
//import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
//import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
//import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
//import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
//import es.in2.issuer.backend.shared.domain.service.JWTService;
//import es.in2.issuer.backend.shared.infrastructure.config.DefaultSignerConfig;
//import es.in2.issuer.backend.shared.infrastructure.config.RemoteSignatureConfig;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.MockitoAnnotations;
//import reactor.core.publisher.Mono;
//import reactor.test.StepVerifier;
//
//import java.util.Collections;
//import java.util.List;
//import java.util.UUID;
//
//import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.Mockito.mock;
//import static org.mockito.Mockito.when;
//
//class LabelCredentialFactoryTest {
//    @Mock
//    private ObjectMapper objectMapper;
//
//    @Mock
//    private DefaultSignerConfig defaultSignerConfig;
//    @Mock
//    private JWTService jwtService;
//    @Mock
//    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
//    @Mock
//    private RemoteSignatureConfig remoteSignatureConfig;
//    @Mock
//    private CredentialProcedureService credentialProcedureService;
//    @InjectMocks
//    private LabelCredentialFactory labelCredentialFactory;
//    private LabelCredential labelCredential;
//    private DetailedIssuer detailedIssuer;
//
//    @BeforeEach
//    void setUp() {
//        MockitoAnnotations.openMocks(this);
//
//        when(defaultSignerConfig.getCommonName()).thenReturn("Common Name");
//        when(defaultSignerConfig.getCountry()).thenReturn("Country");
//        when(defaultSignerConfig.getEmail()).thenReturn("email@example.com");
//        when(defaultSignerConfig.getOrganization()).thenReturn("Organization");
//        when(defaultSignerConfig.getOrganizationIdentifier()).thenReturn("OrgIdentifier");
//        when(defaultSignerConfig.getSerialNumber()).thenReturn("SerialNumber");
//
//        // Create a sample VerifiableCertification
//        labelCredential = LabelCredential.builder()
//                .context(Collections.singletonList("https://www.w3.org/2018/credentials/v1"))
//                .id("urn:uuid:123")
//                .type(Collections.singletonList("VerifiableCertification"))
//                .credentialSubject(
//                        LabelCredential.CredentialSubject.builder()
//                                .company(
//                                        LabelCredential.CredentialSubject.Company.builder()
//                                                .email("company@example.com")
//                                                .build()
//                                )
//                                .product(
//                                        LabelCredential.CredentialSubject.Product.builder()
//                                                .productId("product-123")
//                                                .productName("Sample Product")
//                                                .build()
//                                )
//                                .build()
//                )
//                .validFrom("2023-01-01T00:00:00Z")
//                .validUntil("2024-01-01T00:00:00Z")
//                .atester(LabelCredential.Atester.builder()
//                        .firstName("Test")
//                        .lastName("User")
//                        .country("TestCountry")
//                        .id("did:example:123")
//                        .organization("Test Organization")
//                        .organizationIdentifier("VATES-TEST123")
//                        .build())
//                .build();
//
//        // Create a sample DetailedIssuer
//        detailedIssuer = new DetailedIssuer(
//                "CN=Test Issuer",
//                "ES",
//                "Test Organization",
//                "ORG-123",
//                "VATES-D12345678",
//                "issuer-id-123",
//                ""
//        );
//    }
//
//    @Test
//    void testMapAndBuildLabelCredential() throws Exception {
//        String token = "valid-token";
//        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_SERVER);
//        // Given: A mocked JsonNode input representing the VerifiableCertification
//        String credentialJson = """
//                {
//                    "@context": ["https://www.w3.org/2018/credentials/v1"],
//                    "id": "urn:uuid:%s",
//                    "type": ["VerifiableCertification"],
//                    "credentialSubject": {
//                        "company": {
//                            "address": "1234 Example St.",
//                            "commonName": "Company Name",
//                            "country": "Country",
//                            "email": "company@example.com",
//                            "id": "company-id",
//                            "organization": "Company Organization"
//                        },
//                        "compliance": [{
//                            "id": "compliance-id",
//                            "hash": "1234",
//                            "scope": "compliance-scope",
//                            "standard": "compliance-standard"
//                        }],
//                        "product": {
//                            "productId": "product-id",
//                            "productName": "Product Name",
//                            "productVersion": "1.0"
//                        }
//                    },
//                    "validFrom": "2023-09-07T00:00:00Z",
//                    "validUntil": "2024-09-07T00:00:00Z"
//                }
//                """.formatted(UUID.randomUUID().toString());
//
//        JsonNode credentialNode = objectMapper.readTree(credentialJson);
//
//        // Mock the objectMapper's convertValue method
//        LabelCredential labelCredentialBuild = LabelCredential.builder()
//                .context(List.of("https://www.w3.org/2018/credentials/v1"))
//                .id("urn:uuid:" + UUID.randomUUID())
//                .type(List.of("VerifiableCertification"))
//                .issuer(LabelCredential.Issuer.builder()
//                        .commonName("Issuer Common Name")
//                        .country("Issuer Country")
//                        .id("Issuer ID")
//                        .organization("Issuer Organization")
//                        .build())
//                .credentialSubject(LabelCredential.CredentialSubject.builder()
//                        .company(LabelCredential.CredentialSubject.Company.builder()
//                                .address("1234 Example St.")
//                                .commonName("Company Name")
//                                .country("Country")
//                                .email("company@example.com")
//                                .id("company-id")
//                                .organization("Company Organization")
//                                .build())
//                        .compliance(List.of(LabelCredential.CredentialSubject.Compliance.builder()
//                                .id("compliance-id")
//                                .scope("compliance-scope")
//                                .standard("compliance-standard")
//                                .build()))
//                        .product(LabelCredential.CredentialSubject.Product.builder()
//                                .productId("product-id")
//                                .productName("Product Name")
//                                .productVersion("1.0")
//                                .build())
//                        .build())
//                .validFrom("2023-09-07T00:00:00Z")
//                .validUntil("2024-09-07T00:00:00Z")
//                .signer(LabelCredential.Signer.builder()
//                        .commonName(defaultSignerConfig.getCommonName())
//                        .country(defaultSignerConfig.getCountry())
//                        .emailAddress(defaultSignerConfig.getEmail())
//                        .organization(defaultSignerConfig.getOrganization())
//                        .organizationIdentifier(defaultSignerConfig.getOrganizationIdentifier())
//                        .serialNumber(defaultSignerConfig.getSerialNumber())
//                        .build())
//                .issuer(LabelCredential.Issuer.builder()
//                        .commonName(defaultSignerConfig.getCommonName())
//                        .country(defaultSignerConfig.getCountry())
//                        .id(DID_ELSI + defaultSignerConfig.getOrganizationIdentifier())
//                        .organization(defaultSignerConfig.getOrganization())
//                        .build())
//                .atester(LabelCredential.Atester.builder()
//                        .firstName("John")
//                        .lastName("Doe")
//                        .country("Country")
//                        .id("did:key:1234")
//                        .organization("Organization")
//                        .organizationIdentifier("VATES-1234")
//                        .build())
//                .build();
//
//        SignedJWT signedJWT = mock(SignedJWT.class);
//        Payload jwtPayload = mock(Payload.class);
//        when(signedJWT.getPayload()).thenReturn(jwtPayload);
//
//        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
//        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(LEAR);
//        // We return a valid JSON string so that when parsed, we get "vcJson"
//        when(jwtService.getClaimFromPayload(jwtPayload, "vc_json")).thenReturn("\"vcJson\"");
//        // In this case, we simulate the behavior of objectMapper.readValue:
//        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");
//
//        LEARCredentialEmployee learCredential = getLEARCredentialEmployee();
//        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vcJson")).thenReturn(learCredential);
//
//        when(objectMapper.convertValue(credentialNode, LabelCredential.class)).thenReturn(labelCredentialBuild);
//        when(objectMapper.writeValueAsString(any(LabelCredential.class))).thenReturn("expectedString");
//
//        // When: Calling mapAndBuildVerifiableCertification
//        Mono<CredentialProcedureCreationRequest> resultMono = labelCredentialFactory.mapAndBuildLabelCredential(credentialNode, token, "S");
//
//        // Then: Verify the result
//        StepVerifier.create(resultMono)
//                .expectNextMatches(credentialProcedureCreationRequest ->
//                        credentialProcedureCreationRequest.credentialId() != null &&
//                                credentialProcedureCreationRequest.organizationIdentifier().equals("OrgIdentifier") &&
//                                credentialProcedureCreationRequest.credentialDecoded() != null)
//                .verifyComplete();
//    }
//
//    // Auxiliary methods to create LEARCredentialEmployee objects
//    private LEARCredentialEmployee getLEARCredentialEmployee() {
//        Mandator mandator = Mandator.builder()
//                .organizationIdentifier("VATES-1234")
//                .organization("Organization")
//                .country("Country")
//                .build();
//        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee = LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
//                .id("did:key:1234")
//                .firstName("John")
//                .lastName("Doe")
//                .build();
//        LEARCredentialEmployee.CredentialSubject.Mandate mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
//                .mandator(mandator)
//                .mandatee(mandatee)
//                .build();
//        LEARCredentialEmployee.CredentialSubject credentialSubject = LEARCredentialEmployee.CredentialSubject.builder()
//                .mandate(mandate)
//                .build();
//        return LEARCredentialEmployee.builder()
//                .credentialSubject(credentialSubject)
//                .build();
//    }
//
//    @Test
//    void testBindIssuerAndSigner() {
//        Mono<LabelCredential> result = labelCredentialFactory.bindIssuerAndSigner(
//                labelCredential,
//                detailedIssuer
//        );
//
//        StepVerifier.create(result)
//                .assertNext(updatedCertification -> {
//                    assertNotNull(updatedCertification.issuer());
//                    assertEquals(detailedIssuer.commonName(), updatedCertification.issuer().commonName());
//                    assertEquals(detailedIssuer.country(), updatedCertification.issuer().country());
//                    assertEquals(detailedIssuer.organization(), updatedCertification.issuer().organization());
//                    assertEquals(detailedIssuer.id(), updatedCertification.issuer().id());
//
//                    assertNotNull(updatedCertification.signer());
//                    assertEquals(detailedIssuer.commonName(), updatedCertification.signer().commonName());
//                    assertEquals(detailedIssuer.country(), updatedCertification.signer().country());
//                    assertEquals(detailedIssuer.organization(), updatedCertification.signer().organization());
//                    assertEquals(detailedIssuer.organizationIdentifier(), updatedCertification.signer().organizationIdentifier());
//                    assertEquals(labelCredential.credentialSubject().company().email(), updatedCertification.signer().emailAddress());
//                })
//                .verifyComplete();
//    }
//
//    @Test
//    void testMapIssuerAndSigner_Success() throws Exception {
//        String procedureId = "procedure-123";
//        String decodedCredential = "{\"id\":\"urn:uuid:123\"}";
//
//        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(decodedCredential));
//
//        when(objectMapper.readValue(decodedCredential, LabelCredential.class))
//                .thenReturn(labelCredential);
//
//        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
//                .thenAnswer(invocation -> {
//                    LabelCredential vc = invocation.getArgument(0);
//                    String issuerCommonName = vc.issuer().commonName();
//                    String issuerCountry = vc.issuer().country();
//                    String issuerOrganization = vc.issuer().organization();
//                    String issuerId = vc.issuer().id();
//                    String signerCommonName = vc.signer().commonName();
//                    String signerCountry = vc.signer().country();
//                    String signerOrganization = vc.signer().organization();
//                    String signerOrgId = vc.signer().organizationIdentifier();
//                    String signerEmail = vc.signer().emailAddress();
//                    return "{\"id\":\"" + vc.id() + "\"," +
//                            "\"issuer\":{\"commonName\":\"" + issuerCommonName + "\", \"country\":\"" + issuerCountry + "\", \"organization\":\"" + issuerOrganization + "\", \"id\":\"" + issuerId + "\"}," +
//                            "\"signer\":{\"commonName\":\"" + signerCommonName + "\", \"country\":\"" + signerCountry + "\", \"organization\":\"" + signerOrganization + "\", \"organizationIdentifier\":\"" + signerOrgId + "\", \"emailAddress\":\"" + signerEmail + "\"}}";
//                });
//
//        Mono<String> result = labelCredentialFactory.mapIssuerAndSigner(procedureId, detailedIssuer);
//
//        StepVerifier.create(result)
//                .assertNext(jsonString -> {
//                    System.out.println("Returned JSON: " + jsonString);
//                    assertNotNull(jsonString, "JSON string should not be null");
//                    assertTrue(jsonString.contains(detailedIssuer.commonName()),
//                            "JSON should contain issuer common name");
//                    assertTrue(jsonString.contains(detailedIssuer.country()),
//                            "JSON should contain issuer country");
//                    assertTrue(jsonString.contains(detailedIssuer.organization()),
//                            "JSON should contain issuer organization");
//                    assertTrue(jsonString.contains(detailedIssuer.organizationIdentifier()),
//                            "JSON should contain issuer organization identifier");
//                })
//                .verifyComplete();
//    }
//
//
//    @Test
//    void testMapIssuerAndSigner_InvalidCredentialFormat() throws Exception {
//        String procedureId = "procedure-123";
//        String decodedCredential = "{\"id\":\"urn:uuid:123\"}";
//
//        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(decodedCredential));
//
//        when(objectMapper.readValue(decodedCredential, LabelCredential.class))
//                .thenThrow(new InvalidCredentialFormatException("Invalid credential format"));
//
//        Mono<String> result = labelCredentialFactory.mapIssuerAndSigner(procedureId, detailedIssuer);
//
//        StepVerifier.create(result)
//                .expectError(InvalidCredentialFormatException.class)
//                .verify();
//    }
//}