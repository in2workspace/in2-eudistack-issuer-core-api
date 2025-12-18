package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.service.impl.JWTServiceImpl;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.crypto.CryptoComponent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialPolicyAuthorizationServiceImplIntegrationTest {

    // Use a single source of truth for the admin org id used across tests
    private static final String ADMIN_ORG_ID = "IN2_ADMIN_ORG_ID_FOR_TEST";

    private JWTService jwtService;

    @Mock
    private CryptoComponent cryptoComponent;

    private ObjectMapper objectMapper;

    @Mock
    private VerifierService verifierService;

    @Mock
    private AppConfig appConfig;

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
        // Build real CredentialFactory composed of mocked sub-factories
        objectMapper = new ObjectMapper();
        jwtService = new JWTServiceImpl(objectMapper,cryptoComponent);
        CredentialFactory credentialFactory = new CredentialFactory(
                learCredentialEmployeeFactory,
                learCredentialMachineFactory,
                labelCredentialFactory,
                credentialProcedureService,
                deferredCredentialMetadataService
        );

        // AppConfig must provide the current admin organization id used by the service
        org.mockito.Mockito.lenient()
                .when(appConfig.getAdminOrganizationId())
                .thenReturn(ADMIN_ORG_ID);

        // Construct service with AppConfig first
        policyAuthorizationService = new VerifiableCredentialPolicyAuthorizationServiceImpl(
                appConfig,
                jwtService,
                objectMapper,
                credentialFactory,
                verifierService
        );
    }


    @Test
    void authorize_success_for_LearCredentialEmployee_with_realToken() throws Exception {
        // Arrange
        //Add the token to test
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6d1F2WkVIbXZrMWVPNG5BX0Y4N3lJOVRDa1QxX1FTWHF3X3VUTXZRd2lBIn0.eyJleHAiOjE3NjQzMzI1MzksImlhdCI6MTc2NDMzMjIzOSwiYXV0aF90aW1lIjoxNzY0MzI3MDkwLCJqdGkiOiI5ZmM5ZGZmOS0wNzQwLTQzMDgtOTgwZC1lYjEwMjg1Yzg1NjIiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmRvbWUtbWFya2V0cGxhY2Utc2J4Lm9yZy9yZWFsbXMvZG9tZS1pc3N1ZXIiLCJzdWIiOiI3ZjI4YzJkZi0zMzI3LTQzOTUtODM4OC00NjhmOWEzMWFhNDQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ2Yy1hdXRoLWNsaWVudCIsIm5vbmNlIjoiYzEwOTBmZmFlMDBmNmE2ODU1YzczOWQ0MjliMmM5YTVhNGY0MHNXRVQiLCJzZXNzaW9uX3N0YXRlIjoiMmI4NjA5NGItMmU5Mi00YTk2LTllODEtZmVkYmY1NDg3NDBiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2lzc3Vlci5kb21lLW1hcmtldHBsYWNlLXNieC5vcmciXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtZG9tZS1pc3N1ZXIiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBvZmZsaW5lX2FjY2VzcyBwcm9maWxlIiwic2lkIjoiMmI4NjA5NGItMmU5Mi00YTk2LTllODEtZmVkYmY1NDg3NDBiIiwiY29tbW9uTmFtZSI6Ikplc3VzIFJ1aXoiLCJjb3VudHJ5IjoiRVMiLCJyb2xlIjoiTEVBUiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJzZXJpYWxOdW1iZXIiOiI1NjU2NTY1NlAiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1cm46dXVpZDo5ZDNiNGZkMi05N2JjLTRhZjAtOTBiMC1jZGEyNjRiOTI0ODAiLCJnaXZlbl9uYW1lIjoidGVzdCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImh0dHBzOi8vY3JlZGVudGlhbHMuZXVkaXN0YWNrLmV1Ly53ZWxsLWtub3duL2NyZWRlbnRpYWxzL2xlYXJfY3JlZGVudGlhbF9lbXBsb3llZS93M2MvdjMiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6Imh0dHBzOi8vaXNzdWVyLmRvbWUtbWFya2V0cGxhY2Utc2J4Lm9yZy9iYWNrb2ZmaWNlL3YxL2NyZWRlbnRpYWxzL3N0YXR1cy8xI203QlJGZ0VrVGNTUmRJYW9hUmpmT2ciLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLmRvbWUtbWFya2V0cGxhY2Utc2J4Lm9yZy9iYWNrb2ZmaWNlL3YxL2NyZWRlbnRpYWxzL3N0YXR1cy8xIiwic3RhdHVzTGlzdEluZGV4IjoibTdCUkZnRWtUY1NSZElhb2FSamZPZyIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwidHlwZSI6IlBsYWluTGlzdEVudGl0eSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJtYW5kYXRlIjp7Im1hbmRhdGVlIjp7ImVtYWlsIjoibWlndWVsLm1pckBpbjIuZXMiLCJmaXJzdE5hbWUiOiJ0ZXN0IiwiaWQiOiJkaWQ6a2V5OnpEbmFleE55ZjY3MjM0YVE5Nkt0cUtLc3NabnlXcXJaelFrcFZMRkpYNFo1NnZCbTkiLCJsYXN0TmFtZSI6InRlc3QifSwibWFuZGF0b3IiOnsiY29tbW9uTmFtZSI6Ikplc3VzIFJ1aXoiLCJjb3VudHJ5IjoiRVMiLCJlbWFpbCI6Implc3VzLnJ1aXpAaW4yLmVzIiwiaWQiOiJkaWQ6ZWxzaTpWQVRFUy1CNjA2NDU5MDAiLCJvcmdhbml6YXRpb24iOiJJTjIgSU5HRU5JRVJJQSBERSBMQSBJTkZPUk1BQ0lPTiBTT0NJRURBRCBMSU1JVEFEQSIsIm9yZ2FuaXphdGlvbklkZW50aWZpZXIiOiJWQVRFUy1CNjA2NDU5MDAiLCJzZXJpYWxOdW1iZXIiOiI1NjU2NTY1NlAifSwicG93ZXIiOlt7ImFjdGlvbiI6WyJFeGVjdXRlIl0sImRvbWFpbiI6IkRPTUUiLCJmdW5jdGlvbiI6Ik9uYm9hcmRpbmciLCJ0eXBlIjoiZG9tYWluIn1dfX0sImRlc2NyaXB0aW9uIjoiVmVyaWZpYWJsZSBDcmVkZW50aWFsIGZvciBlbXBsb3llZXMgb2YgYW4gb3JnYW5pemF0aW9uIiwiaWQiOiJ1cm46dXVpZDo5ZDNiNGZkMi05N2JjLTRhZjAtOTBiMC1jZGEyNjRiOTI0ODAiLCJpc3N1ZXIiOnsiY29tbW9uTmFtZSI6IlNlYWwgU2lnbmF0dXJlIENyZWRlbnRpYWxzIGluIFNCWCBmb3IgdGVzdGluZyIsImNvdW50cnkiOiJFUyIsImlkIjoiZGlkOmVsc2k6VkFURVMtQjYwNjQ1OTAwIiwib3JnYW5pemF0aW9uIjoiSU4yIiwib3JnYW5pemF0aW9uSWRlbnRpZmllciI6IlZBVEVTLUI2MDY0NTkwMCIsInNlcmlhbE51bWJlciI6IkI0NzQ0NzU2MCJ9LCJ0eXBlIjpbIkxFQVJDcmVkZW50aWFsRW1wbG95ZWUiLCJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJ2YWxpZEZyb20iOiIyMDI1LTExLTI4VDEwOjE4OjUxLjc3ODg4Mjg3OFoiLCJ2YWxpZFVudGlsIjoiMjAyNi0xMS0yOFQxMDoxODo1MS43Nzg4ODI4NzhaIn0sIm9yZ2FuaXphdGlvbklkZW50aWZpZXIiOiJWQVRFUy1CNjA2NDU5MDAiLCJvcmdhbml6YXRpb24iOiJJTjIgSU5HRU5JRVJJQSBERSBMQSBJTkZPUk1BQ0lPTiBTT0NJRURBRCBMSU1JVEFEQSIsIm5hbWUiOiJ0ZXN0IHRlc3QiLCJmYW1pbHlfbmFtZSI6InRlc3QiLCJlbWFpbCI6Im1pZ3VlbC5taXJAaW4yLmVzIn0.HTrFfOUmdi1ZqrdsqLTDAxUsamr_GD5dcNK_IfOuwK5mHUqGMIugtD5GZB9IUbUZBVjvd0VmwX0-mSNaaUP4JnbzpAQAuBzvOUlJq0vLeWS0TPOWmr0XkotknfsO3U3CQPBmlwgH5tLqaaeLiNxOC_xX9_scXwnltTxnaV5v92OjdiBGIsTyNdckUG4PJUn2gQdRPWGY5KOGrkaraahMnmAP3nKKSYRHbEGX0Hja6Y5ylmC61JyNZR0lf9kK7MQTrsno6TOqFIaqTF7NzKYrfhleMlCh0uxSNVwJ5sQH9IfPz3MbAhleleMEfjKb1DF7aKPHFZMOO116JBEwKrrL8A";
        String json = """
                {
                    "life_span": {
                        "end_date_time": "2025-04-02 09:23:22.637345122 +0000 UTC",
                        "start_date_time": "2024-04-02 09:23:22.637345122 +0000 UTC"
                    },
                    "mandatee": {
                        "email": "example@in2.es",
                        "firstName": "Jhon",
                        "lastName": "Doe",
                        "mobile_phone": "+34666336699"
                    },
                    "mandator": {
                        "commonName": "IN2",
                        "country": "ES",
                        "email": "rrhh@in2.es",
                        "organization": "IN2, Ingeniería de la Información, S.L.",
                        "organizationIdentifier": "VATES-B60645900",
                        "serialNumber": "3424320"
                    },
                    "power": [
                        {
                            "id": "ad9b1509-60ea-47d4-9878-18b581d8e19b",
                            "tmf_action": [
                                "Create",
                                "Update"
                            ],
                            "tmf_domain": "DOME",
                            "tmf_function": "ProductOffering",
                            "tmf_type": "Domain"
                        }
                    ]
                }
                """;
        JsonNode jsonNode = objectMapper.readTree(json);
        //!! para evitar tocar todas las clases mockeadas, recreamos la credencial en este punto.
        LEARCredentialEmployee learCredential = getLEARCredentialEmployee();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(any())).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, jsonNode, "dummy-id-token");

        // Assert
        StepVerifier.create(result).verifyComplete();
    }


    private LEARCredentialEmployee getLEARCredentialEmployee() {
        Mandator mandator = Mandator.builder()
                //.organizationIdentifier(ADMIN_ORG_ID)
                .organizationIdentifier("VATES-B60645900")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:zDnaexNyf67234aQ96KtqKKssZnyWqrZzQkpVLFJX4Z56vBm9")
                        .firstName("test")
                        .lastName("test")
                        .email("miguel.mir@in2.es")
                        .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .domain("DOME")
                .type("Domain")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }



}
