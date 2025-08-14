package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialPolicyAuthorizationServiceImplTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private VerifierService verifierService;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    @Mock
    private LabelCredentialFactory labelCredentialFactory;
    @Mock
    private LEARCredentialMachineFactory learCredentialMachineFactory;
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;


    @InjectMocks
    private VerifiableCredentialPolicyAuthorizationServiceImpl policyAuthorizationService;

    @BeforeEach
    void setUp() {
        // Creamos una instancia real de CredentialFactory, pasando los mocks necesarios
        CredentialFactory credentialFactory = new CredentialFactory(learCredentialEmployeeFactory, learCredentialMachineFactory, labelCredentialFactory, credentialProcedureService, deferredCredentialMetadataService);

        // Inicializamos policyAuthorizationService con las dependencias adecuadas
        policyAuthorizationService = new VerifiableCredentialPolicyAuthorizationServiceImpl(
                jwtService,
                objectMapper,
                credentialFactory,
                verifierService
        );
    }

    @Test
    void authorize_success_withLearCredentialEmployee() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        // Create and configure the simulated Payload
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        // We use a real ObjectMapper to create the JsonNode we need
        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployee();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
    }

    @Test
    void authorize_failure_dueToInvalidCredentialType() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"InvalidCredentialType\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: Credential type 'LEARCredentialEmployee' or 'LEARCredentialMachine' is required."))
                .verify();
    }

    @Test
    void authorize_failure_dueToUnsupportedSchema() throws Exception {
        // Arrange
        String token = "valid-token";
        String schema = "UnsupportedSchema";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployee();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, schema, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: Unsupported schema"))
                .verify();
    }

    @Test
    void authorize_failure_dueToInvalidToken(){
        String token = "invalid-token";
        JsonNode payload = mock(JsonNode.class);

        when(jwtService.parseJWT(token)).thenThrow(new ParseErrorException("Invalid token"));

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof ParseErrorException &&
                                throwable.getMessage().contains("Invalid token"))
                .verify();
    }

    @Test
    void authorize_failure_dueToIssuancePoliciesNotMet() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "some-other-issuer");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_failure_dueToVerifiableCertificationPolicyNotMet() throws Exception {
        // Arrange
        String token = "valid-token";
        String idToken = "dummy-id-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialMachine\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "some-other-issuer");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialMachine learCredential = getLEARCredentialMachineWithInvalidPolicy();
        when(learCredentialMachineFactory.mapStringToLEARCredentialMachine(vcClaim)).thenReturn(learCredential);

        SignedJWT idTokenSignedJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenSignedJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenSignedJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");

        LEARCredentialEmployee idTokenCredential = getLEARCredentialEmployeeForCertification();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vcJson")).thenReturn(idTokenCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, idToken);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: VerifiableCertification does not meet the issuance policy."))
                .verify();
    }

    @Test
    void authorize_success_withVerifiableCertification() throws Exception {
        // Arrange
        String token = "valid-token";
        String idToken = "dummy-id-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialMachine\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "external-verifier");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Emulate that the machine factory returns a credential that meets the policy
        LEARCredentialMachine learCredential = getLEARCredentialMachineForCertification();
        when(learCredentialMachineFactory.mapStringToLEARCredentialMachine(vcClaim)).thenReturn(learCredential);

        // --- Mocks para el id_token ---
        SignedJWT idTokenSignedJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenSignedJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenSignedJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");
        LEARCredentialEmployee idTokenCredential = getLEARCredentialEmployeeForCertification();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vcJson")).thenReturn(idTokenCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, idToken);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
    }
    @Test
    void authorize_failure_withLearCredentialEmployerRoleLear() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "external-verifier");
        String roleClaim =LEAR;
        payloadMap.put(ROLE, roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeForCertification();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_success_withMandatorIssuancePolicyValid() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();

        LEARCredentialEmployee.CredentialSubject.Mandate mandateFromPayload = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(Mandator.builder()
                        .organizationIdentifier(learCredential.credentialSubject().mandate().mandator().organizationIdentifier())
                        .serialNumber(learCredential.credentialSubject().mandate().mandator().serialNumber())
                        .country(learCredential.credentialSubject().mandate().mandator().country())
                        .commonName(learCredential.credentialSubject().mandate().mandator().commonName())
                        .emailAddress(learCredential.credentialSubject().mandate().mandator().emailAddress())
                        .build())
                .power(Collections.singletonList(
                        Power.builder()
                                .function("ProductOffering")
                                .action(List.of("Create", "Update", "Delete"))
                                .build()))
                .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class)).thenReturn(mandateFromPayload);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
    }

    @Test
    void authorize_failure_dueToInvalidPayloadPowers() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();

        LEARCredentialEmployee.CredentialSubject.Mandate mandateFromPayload = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(Mandator.builder()
                        .organizationIdentifier(learCredential.credentialSubject().mandate().mandator().organizationIdentifier())
                        .serialNumber(learCredential.credentialSubject().mandate().mandator().serialNumber())
                        .country(learCredential.credentialSubject().mandate().mandator().country())
                        .commonName(learCredential.credentialSubject().mandate().mandator().commonName())
                        .emailAddress(learCredential.credentialSubject().mandate().mandator().emailAddress())
                        .build())
                .power(Collections.singletonList(
                        Power.builder()
                                .function("OtherFunction")
                                .action("SomeAction")
                                .build()))
                .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class)).thenReturn(mandateFromPayload);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_success_withLearCredentialMachine() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        // El vcClaim indica que se trata de una credencial de máquina
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        StepVerifier.create(result)
                .verifyComplete();
    }

    @Test
    void authorize_failure_withLearCredentialMachine_dueToPolicy() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, "LEAR_CREDENTIAL_MACHINE", payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException)
                .verify();
    }

    @Test
    void authorize_failure_dueToUnauthorizedRoleIsBlank() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = "\"\"";
        payloadMap.put(ROLE,roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("Access denied: Role is empty"))
                .verify();
    }

    @Test
    void authorize_failure_dueToUnauthorizedRoleWithVerifiableCertification() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = LER;
        payloadMap.put(ROLE,roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("Access denied: Unauthorized Role '"+roleClaim+"'"))
                .verify();
    }

    @Test
    void authorize_failure_dueToSYS_ADMINOrLERRole() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = SYS_ADMIN;
        payloadMap.put(ROLE,roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("The request is invalid. The roles 'SYSADMIN' and 'LER' currently have no defined permissions.")
                )
                .verify();
    }

    @Test
    void authorize_failureDueToUnknownRole() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = "ADMIN";
        payloadMap.put(ROLE,roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("Access denied: Unauthorized Role '"+roleClaim+"'"))
                .verify();
    }

    @Test
    void authorize_failureDueToNullRole() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim =null;
        payloadMap.put(ROLE,roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("Access denied: Role is empty"))
                .verify();
    }
    
    // Auxiliary methods to create LEARCredentialEmployee objects
    private LEARCredentialEmployee getLEARCredentialEmployee() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier(IN2_ORGANIZATION_IDENTIFIER)
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee = LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                .id("did:key:1234")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(mandator)
                .mandatee(mandatee)
                .power(Collections.singletonList(power))
                .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject = LEARCredentialEmployee.CredentialSubject.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialEmployee getLEARCredentialEmployeeWithDifferentOrg() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("OTHER_ORGANIZATION")
                .commonName("SomeOtherOrganization")
                .country("ES")
                .emailAddress("someaddres@example.com")
                .serialNumber("123456")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee = LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                .id("did:key:1234")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(mandator)
                .mandatee(mandatee)
                .power(Collections.singletonList(power))
                .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject = LEARCredentialEmployee.CredentialSubject.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachineForCertification() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator = LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                .organization("SomeOrganization")
                .build();
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee = LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                .id("did:key:1234")
                .build();
        Power power = Power.builder()
                .function("Certification")
                .action("Attest")
                .build();
        LEARCredentialMachine.CredentialSubject.Mandate mandate = LEARCredentialMachine.CredentialSubject.Mandate.builder()
                .mandator(mandator)
                .mandatee(mandatee)
                .power(Collections.singletonList(power))
                .build();
        LEARCredentialMachine.CredentialSubject credentialSubject = LEARCredentialMachine.CredentialSubject.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialEmployee getLEARCredentialEmployeeForCertification() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("SomeOrganization")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee = LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                .id("did:key:1234")
                .firstName("Jane")
                .lastName("Doe")
                .email("jane.doe@example.com")
                .build();
        Power power = Power.builder()
                .function("Certification")
                .action("Attest")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(mandator)
                .mandatee(mandatee)
                .power(Collections.singletonList(power))
                .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject = LEARCredentialEmployee.CredentialSubject.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachine() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator = LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                .organization(IN2_ORGANIZATION_IDENTIFIER)
                .build();
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee = LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                .id("did:key:1234")
                .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
        LEARCredentialMachine.CredentialSubject.Mandate mandate = LEARCredentialMachine.CredentialSubject.Mandate.builder()
                .mandator(mandator)
                .mandatee(mandatee)
                .power(Collections.singletonList(power))
                .build();
        LEARCredentialMachine.CredentialSubject credentialSubject = LEARCredentialMachine.CredentialSubject.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachineWithInvalidPolicy() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator = LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                .organization(IN2_ORGANIZATION_IDENTIFIER)
                .build();
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .build();
        // Create an empty list of powers to simulate that the policy is not met
        List<Power> emptyPowers = Collections.emptyList();
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(emptyPowers)
                        .build();
        LEARCredentialMachine.CredentialSubject credentialSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }

    @Test
    void authorize_machine_success_whenMandatorAllowed_and_OnboardingExecute() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee signerEmployee = getLEARCredentialEmployee();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim))
                .thenReturn(signerEmployee);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void isLearCredentialEmployeeMandatorOrganizationIdentifierAllowedSignerLEARCredentialMachine_returnsTrue_whenOrgMatches() throws Exception {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier(IN2_ORGANIZATION_IDENTIFIER)
                .build();

        Method method = VerifiableCredentialPolicyAuthorizationServiceImpl.class
                .getDeclaredMethod("isLearCredentialEmployeeMandatorOrganizationIdentifierAllowedSignerLEARCredentialMachine", Mandator.class);
        method.setAccessible(true);

        boolean result = (boolean) method.invoke(policyAuthorizationService, mandator);
        assertTrue(result);
    }

    @Test
    void isLearCredentialEmployeeMandatorOrganizationIdentifierAllowedSignerLEARCredentialMachine_returnsFalse_whenOrgDoesNotMatch() throws Exception {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("OTHER_ORG")
                .build();

        Method method = VerifiableCredentialPolicyAuthorizationServiceImpl.class
                .getDeclaredMethod("isLearCredentialEmployeeMandatorOrganizationIdentifierAllowedSignerLEARCredentialMachine", Mandator.class);
        method.setAccessible(true);

        boolean result = (boolean) method.invoke(policyAuthorizationService, mandator);
        assertFalse(result);
    }


}


