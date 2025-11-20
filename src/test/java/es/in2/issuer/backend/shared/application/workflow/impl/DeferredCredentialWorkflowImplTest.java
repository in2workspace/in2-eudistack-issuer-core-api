package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.PendingCredentials;
import es.in2.issuer.backend.shared.domain.model.dto.SignedCredentials;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeferredCredentialWorkflowImplTest {
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private EmailService emailService;

    @InjectMocks
    private DeferredCredentialWorkflowImpl deferredCredentialWorkflow;

    private ObjectMapper realObjectMapper;

    @BeforeEach
    void setup() {
        this.realObjectMapper = new ObjectMapper();
    }

    @Test
    void getPendingCredentialsByOrganizationId(){
        String organizationId = "4321";
        String expectedCredential = "Credential1";
        PendingCredentials expectedPendingCredentials = PendingCredentials.builder()
                .credentials(List.of(PendingCredentials.CredentialPayload.builder()
                        .credential(expectedCredential)
                        .build()))
                .build();

        when(credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationId))
                .thenReturn(Flux.just(expectedCredential));

        StepVerifier.create(deferredCredentialWorkflow.getPendingCredentialsByOrganizationId(organizationId))
                .expectNext(expectedPendingCredentials)
                .verifyComplete();
    }

    @Test
    void updateSignedCredentials_shouldCallGetCredentialOfferEmailInfo_whenModeIsAsync() {
        // given
        String procedureId = "1234";
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ2YyI6eyJpZCI6Im15SWQifX0.signature";

        SignedCredentials.SignedCredential signedCredential =
                SignedCredentials.SignedCredential.builder()
                        .credential(jwt)
                        .build();

        SignedCredentials signedCredentials =
                SignedCredentials.builder()
                        .credentials(List.of(signedCredential))
                        .build();

        // Mock the JWT parsing and JSON handling part
        when(credentialProcedureService.updatedEncodedCredentialByCredentialProcedureId(jwt, procedureId))
                .thenReturn(Mono.just(procedureId));

        when(deferredCredentialMetadataService.updateVcByProcedureId(jwt, procedureId))
                .thenReturn(Mono.empty());

        when(deferredCredentialMetadataService.getOperationModeByProcedureId(procedureId))
                .thenReturn(Mono.just("ASYNC"));

        // when + then
        StepVerifier.create(deferredCredentialWorkflow.updateSignedCredentials(signedCredentials, procedureId))
                .verifyComplete();
    }

    //todo
//    @Test
//    void updateSignedCredentialsLearCredentialEmployee() throws JsonProcessingException {
//        String procedureId = UUID.randomUUID().toString();
//        CredentialProcedure credentialProcedure = new CredentialProcedure();
//        credentialProcedure.setCredentialType(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
//        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
//        String credential = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
//        String expectedEmail = "juan.perez@mail.com";
//        String expectedFirstName = "Juan";
//        String expectedId = "390ecd06-4e56-483a-b550-18d93a4bf9e3";
//
//        List<SignedCredentials.SignedCredential> credentials = List.of(SignedCredentials.SignedCredential.builder()
//                .credential(credential)
//                .build()
//        );
//
//        SignedCredentials signedCredentials = SignedCredentials.builder()
//                .credentials(credentials)
//                .build();
//
//        // Example JSON for parsing
//        String json = """ ... """;
//        ObjectMapper objectMapper2 = new ObjectMapper();
//        JsonNode jsonNode = objectMapper2.readTree(json);
//
//        when(objectMapper.readTree(anyString())).thenReturn(jsonNode);
//
//        when(credentialProcedureService.updatedEncodedCredentialByCredentialId(
//                signedCredentials.credentials().get(0).credential(), expectedId))
//                .thenReturn(Mono.just(procedureId));
//
//        when(deferredCredentialMetadataService.updateVcByProcedureId(credential, procedureId))
//                .thenReturn(Mono.empty());
//
//        when(emailService.sendCredentialSignedNotification(
//                expectedEmail,"Credential Ready", expectedFirstName, "You can now use it with your Wallet."))
//                .thenReturn(Mono.empty());
//
//        when(deferredCredentialMetadataService.getOperationModeByProcedureId(procedureId))
//                .thenReturn(Mono.just("A"));
//
//        StepVerifier.create(deferredCredentialWorkflow.updateSignedCredentials(signedCredentials))
//                .verifyComplete();
//    }
//
//    @Test
//    void buildNotificationData_mandatee() throws Exception {
//        String json = """
//            {
//              "vc": {
//                "credentialSubject": {
//                  "mandate": {
//                    "mandatee": {
//                      "email": "foo@example.com",
//                      "firstName": "Foo"
//                    }
//                  }
//                }
//              }
//            }
//            """;
//        JsonNode node = realObjectMapper.readTree(json);
//
//        Object result = ReflectionTestUtils.invokeMethod(
//                deferredCredentialWorkflow,
//                "buildNotificationData",
//                node
//        );
//        Class<?> ndClass = result.getClass();
//        Field emailF     = ndClass.getDeclaredField("email");
//        Field firstNameF = ndClass.getDeclaredField("firstName");
//        Field additionalInfoF  = ndClass.getDeclaredField("additionalInfo");
//        emailF.setAccessible(true);
//        firstNameF.setAccessible(true);
//        additionalInfoF.setAccessible(true);
//
//        assertEquals("foo@example.com", emailF.get(result));
//        assertEquals("Foo",              firstNameF.get(result));
//        assertEquals("You can now use it with your Wallet.", additionalInfoF.get(result));
//    }
//
//    @Test
//    void buildNotificationData_company() throws Exception {
//        // Build a JSON object containing credentialSubject.company
//        String json = """
//        {
//          "vc": {
//            "credentialSubject": {
//              "company": {
//                "email": "bar@corp.com",
//                "commonName": "BarCorp"
//              }
//            }
//          }
//        }
//        """;
//        JsonNode node = realObjectMapper.readTree(json);
//
//        Object result = ReflectionTestUtils.invokeMethod(
//                deferredCredentialWorkflow,
//                "buildNotificationData",
//                node
//        );
//
//        Class<?> ndClass      = result.getClass();
//        Field emailF          = ndClass.getDeclaredField("email");
//        Field firstNameF      = ndClass.getDeclaredField("firstName");
//        Field additionalInfoF = ndClass.getDeclaredField("additionalInfo");
//        emailF.setAccessible(true);
//        firstNameF.setAccessible(true);
//        additionalInfoF.setAccessible(true);
//
//        assertEquals("bar@corp.com", emailF.get(result));
//        assertEquals("BarCorp", firstNameF.get(result));
//        assertEquals("It is now ready to be applied to your product.", additionalInfoF.get(result));
//    }
//
//    @Test
//    void buildNotificationData_missingFields_throws() throws Exception {
//        // Neither mandate nor company present
//        String json = """
//            {
//              "vc": {
//                "credentialSubject": {
//                  "other": {}
//                }
//              }
//            }
//            """;
//        JsonNode node = realObjectMapper.readTree(json);
//
//        assertThrows(
//                ResponseStatusException.class,
//                () -> ReflectionTestUtils.invokeMethod(
//                        deferredCredentialWorkflow,
//                        "buildNotificationData",
//                        node
//                )
//        );
//    }
}
