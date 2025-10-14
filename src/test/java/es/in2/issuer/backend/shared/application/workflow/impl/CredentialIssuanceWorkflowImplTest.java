package es.in2.issuer.backend.shared.application.workflow.impl;


import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.model.dto.VerifierOauth2AccessToken;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.DeferredCredentialMetadata;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.WebClientConfig;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.OperationNotSupportedException;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuanceServiceImplTest {

    @Mock
    private CredentialDeliveryService credentialDeliveryService;

    @Mock
    private VerifiableCredentialService verifiableCredentialService;

    @Mock
    private ProofValidationService proofValidationService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private EmailService emailService;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private IssuerApiClientTokenService issuerApiClientTokenService;

    @Mock
    private CredentialSignerWorkflow credentialSignerWorkflow;

    @Mock
    private WebClientConfig webClientConfig;

    @Mock
    private VerifiableCredentialPolicyAuthorizationService verifiableCredentialPolicyAuthorizationService;

    @Mock
    private TrustFrameworkService trustFrameworkService;

    @Mock
    private LEARCredentialEmployeeFactory credentialEmployeeFactory;

    @Mock
    private M2MTokenService m2MTokenService;

    @Mock
    private CredentialIssuerMetadataService credentialIssuerMetadataService;

    @InjectMocks
    private CredentialIssuanceWorkflowImpl verifiableCredentialIssuanceWorkflow;

    @Test
    void unsupportedFormatErrorExceptionTest() {
        String processId = "1234";
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder().payload(null).schema("LEARCredentialEmployee").format("json_ldp").operationMode("S").build();
        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, "token", null))
                .expectError(FormatUnsupportedException.class)
                .verify();
    }

    @Test
    void unsupportedOperationModeExceptionTest() {
        String processId = "1234";
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest =
                PreSubmittedCredentialDataRequest.builder()
                        .payload(null)
                        .schema("LEARCredentialEmployee")
                        .format(JWT_VC_JSON)
                        .operationMode("F")
                        .build();

        StepVerifier.create(
                        verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, "token", null)
                )
                .expectError(OperationNotSupportedException.class)
                .verify();
    }
    // TODO
    //    @Test
    //    void operationNotSupportedExceptionDueInvalidResponseUriTest() {
    //        String processId = "1234";
    //        String token = "token";
    //        String type = "VerifiableCertification";
    //        String idToken = "idToken";
    //        JsonNode jsonNode = mock(JsonNode.class);
    //
    //        PreSubmittedCredentialRequest preSubmittedCredentialRequest = PreSubmittedCredentialRequest.builder().payload(jsonNode).schema("VerifiableCertification").format(JWT_VC).operationMode("S").responseUri("").build();
    //        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, idToken)).thenReturn(Mono.empty());
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialRequest, token, idToken))
    //                .expectError(OperationNotSupportedException.class)
    //                .verify();
    //    }

    @Test
    void completeWithdrawLEARProcessSyncSuccess() throws JsonProcessingException {
        String processId = "1234";
        String type = "LEARCredentialEmployee";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String issuerUiExternalDomain = "https://example.com";
        String token = "token";
        String idToken = "idToken";
        String expectedEmail = "example@in2.es";
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
                        "organizationIdentifier": "VATES-B26246436",
                        "serialNumber": "3424320"
                    },
                    "power": [
                        {
                            "id": "6b8f3137-a57a-46a5-97e7-1117a20142fv",
                            "tmf_domain": "DOME",
                            "tmf_function": "DomePlatform",
                            "tmf_type": "Domain",
                            "tmf_action": [
                                "Operator",
                                "Customer",
                                "Provider"
                            ]
                        },
                        {
                            "id": "6b8f3137-a57a-46a5-97e7-1117a20142fb",
                            "tmf_action": "Execute",
                            "tmf_domain": "DOME",
                            "tmf_function": "Onboarding",
                            "tmf_type": "Domain"
                        },
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
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(json);
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder().payload(jsonNode).schema("LEARCredentialEmployee").format(JWT_VC_JSON).operationMode("S").build();
        String transactionCode = "4321";

        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, idToken)).thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(processId, preSubmittedCredentialDataRequest, expectedEmail)).thenReturn(Mono.just(transactionCode));
        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);
        when(emailService.sendCredentialActivationEmail("example@in2.es", "Activate your new credential", issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode, knowledgebaseWalletUrl, "IN2, Ingeniería de la Información, S.L.")).thenReturn(Mono.empty());
        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, token, idToken))
                .verifyComplete();
    }

    @Test
    void completeWithdrawLEARProcessSyncFailureOnEmailSending() throws JsonProcessingException {
        String processId = "1234";
        String type = "LEARCredentialEmployee";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String issuerUiExternalDomain = "https://example.com";
        String token = "token";
        String expectedEmail = "example@in2.es";
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
                        "organizationIdentifier": "VATES-B26246436",
                        "serialNumber": "3424320"
                    },
                    "power": [
                        {
                            "id": "6b8f3137-a57a-46a5-97e7-1117a20142fv",
                            "tmf_domain": "DOME",
                            "tmf_function": "DomePlatform",
                            "tmf_type": "Domain",
                            "tmf_action": [
                                "Operator",
                                "Customer",
                                "Provider"
                            ]
                        },
                        {
                            "id": "6b8f3137-a57a-46a5-97e7-1117a20142fb",
                            "tmf_action": "Execute",
                            "tmf_domain": "DOME",
                            "tmf_function": "Onboarding",
                            "tmf_type": "Domain"
                        },
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
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(json);
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder()
                .payload(jsonNode)
                .schema("LEARCredentialEmployee")
                .format(JWT_VC_JSON)
                .operationMode("S")
                .build();
        String transactionCode = "4321";

        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, null)).thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(processId,preSubmittedCredentialDataRequest, expectedEmail)).thenReturn(Mono.just(transactionCode));
        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);

        // Simulated failure when sending the email
        when(emailService.sendCredentialActivationEmail(
                "example@in2.es",
                "Activate your new credential",
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
                knowledgebaseWalletUrl,
                "IN2, Ingeniería de la Información, S.L."))
                .thenReturn(Mono.error(new RuntimeException("Email sending failed")));

        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, token, null))
                .expectErrorMatches(throwable ->
                        throwable instanceof EmailCommunicationException &&
                                throwable.getMessage().contains(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .verify();
    }

    // TODO
    //    @Test
    //    void completeWithdrawVerifiableCertificationProcessSuccess() throws JsonProcessingException {
    //        String processId = "1234";
    //        String type = "VerifiableCertification";
    //        String procedureId = "procedureId";
    //        String token = "token";
    //        String idToken = "idToken";
    //        String json = """
    //                {
    //                    "type": [
    //                        "ProductOfferingCredential"
    //                    ],
    //                    "issuer": {
    //                        "commonName": "IssuerCommonName",
    //                        "country": "ES",
    //                        "id": "did:web:issuer-test.com",
    //                        "organization": "Issuer Test"
    //                    },
    //                    "credentialSubject": {
    //                        "company": {
    //                            "address": "address",
    //                            "commonName": "commonName",
    //                            "country": "ES",
    //                            "email": "email@email.com",
    //                            "id": "did:web:commonname.com",
    //                            "organization": "Organization Name"
    //                        },
    //                        "compliance": [
    //                            {
    //                                "scope": "Scope Name",
    //                                "standard": "standard"
    //                            }
    //                        ],
    //                        "product": {
    //                            "productId": "productId",
    //                            "productName": "Product Name",
    //                            "productVersion": "0.1"
    //                        }
    //                    },
    //                    "issuanceDate": "2024-08-22T00:00:00Z",
    //                    "validFrom": "2024-08-22T00:00:00Z",
    //                    "expirationDate": "2025-08-22T00:00:00Z"
    //                }
    //                """;
    //        ObjectMapper objectMapper = new ObjectMapper();
    //        JsonNode jsonNode = objectMapper.readTree(json);
    //        PreSubmittedCredentialRequest preSubmittedCredentialRequest = PreSubmittedCredentialRequest.builder().payload(jsonNode).schema("VerifiableCertification").format(JWT_VC_JSON).responseUri("https://example.com/1234").operationMode("S").build();
    //
    //
    //        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, idToken)).thenReturn(Mono.empty());
    //        when(verifiableCredentialService.generateVc(processId, preSubmittedCredentialRequest.schema(),preSubmittedCredentialRequest)).thenReturn(Mono.just(procedureId));
    //        when(issuerApiClientTokenService.getClientToken()).thenReturn(Mono.just("internalToken"));
    //        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId)).thenReturn(Mono.empty());
    //        when(m2MTokenService.getM2MToken()).thenReturn(Mono.just(new VerifierOauth2AccessToken("", "", "")));
    //        when(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(BEARER_PREFIX + "internalToken", procedureId, JWT_VC_JSON)).thenReturn(Mono.just("signedCredential"));
    //        when(credentialDeliveryService.sendVcToResponseUri(
    //                anyString(),
    //                anyString(),
    //                anyString(),
    //                anyString(),
    //                anyString()
    //        )).thenReturn(Mono.empty());
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialRequest, token, idToken))
    //                .verifyComplete();
    //    }

    //    @Test
    //    void generateVerifiableCredentialResponseSyncSuccess() {
    //        String processId = "1234";
    //        CredentialRequest credentialRequest = CredentialRequest.builder()
    //                .credentialConfigurationId(JWT_VC)
    //                .proofs(Proofs.builder()
    //                        .jwt(List.of("eyJraWQiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MjekRuYWVuMjN3TTc2Z3BpU0xIa3U0YkZEYnNzVlM5c3R5OXgzSzd5VnFqYlNkVFBXQyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjE3MTI5MTcwNDAsImlhdCI6MTcxMjA1MzA0MCwibm9uY2UiOiI4OVh4bXdMMlJtR2wyUlp1LU1UU3lRPT0ifQ.DdaaNm4vTn60njLtAQ7Q5oGsQILfA-5h9-sv4MBcVyNBAfSrUUajZqlUukT-5Bx8EqocSvf0RIFRHLcvO9_LMg"))
    //                        .build())
    //                .build();
    //        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";
    //        String jti = "fcca7591-6742-4c30-949c-ee9707196756";
    //        String did = "did:key:zDnaen23wM76gpiSLHku4bFDbssVS9sty9x3K7yVqjbSdTPWC";
    //        CredentialResponse credentialResponse = CredentialResponse.builder()
    //                .credentials(List.of(
    //                        CredentialResponse.Credential.builder()
    //                                .credential("credential")
    //                                .build()))
    //                .transactionId("4321")
    //                .build();
    //        String procedureId = "123456";
    //        String decodedCredential = "decodedCredential";
    //
    //        when(proofValidationService.isProofValid(credentialRequest.proofs().jwt().get(0), token)).thenReturn(Mono.just(true));
    //        when(verifiableCredentialService.buildCredentialResponse(processId, did, jti, token)).thenReturn(Mono.just(credentialResponse));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just(procedureId));
    //        when(deferredCredentialMetadataService.getOperationModeByAuthServerNonce(jti)).thenReturn(Mono.just("S"));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just("procedureId"));
    //        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId("procedureId")).thenReturn(Mono.empty());
    //        when(credentialProcedureService.getCredentialStatusByProcedureId("procedureId")).thenReturn(Mono.just(CredentialStatus.DRAFT.toString()));
    //        when(credentialProcedureService.getDecodedCredentialByProcedureId("procedureId")).thenReturn(Mono.just(decodedCredential));
    //
    //        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
    //        LEARCredentialEmployee.CredentialSubject credentialSubject = mock(LEARCredentialEmployee.CredentialSubject.class);
    //        LEARCredentialEmployee.CredentialSubject.Mandate mandate = mock(LEARCredentialEmployee.CredentialSubject.Mandate.class);
    //        Mandator mandator = mock(Mandator.class);
    //
    //        when(learCredentialEmployee.credentialSubject()).thenReturn(credentialSubject);
    //        when(credentialSubject.mandate()).thenReturn(mandate);
    //        when(mandate.mandator()).thenReturn(mandator);
    //
    //        String organizationIdentifier = "organizationIdentifier";
    //        when(mandator.organizationIdentifier()).thenReturn(organizationIdentifier);
    //
    //        String organizationIdentifierDid = DID_ELSI + organizationIdentifier;
    //
    //        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential)).thenReturn(learCredentialEmployee);
    //        when(trustFrameworkService.validateDidFormat(processId, organizationIdentifierDid)).thenReturn(Mono.just(true));
    //        when(trustFrameworkService.registerDid(processId, organizationIdentifierDid)).thenReturn(Mono.empty());
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, token))
    //                .expectNext(credentialResponse)
    //                .verifyComplete();
    //    }
    //
    //    @Test
    //    void generateVerifiableCredentialResponseFailedProofException() {
    //        String processId = "1234";
    //        CredentialRequest credentialRequest = CredentialRequest.builder()
    //                .credentialConfigurationId(JWT_VC)
    //                .proofs(Proofs.builder()
    //                        .jwt(List.of("eyJraWQiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MjekRuYWVuMjN3TTc2Z3BpU0xIa3U0YkZEYnNzVlM5c3R5OXgzSzd5VnFqYlNkVFBXQyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjE3MTI5MTcwNDAsImlhdCI6MTcxMjA1MzA0MCwibm9uY2UiOiI4OVh4bXdMMlJtR2wyUlp1LU1UU3lRPT0ifQ.DdaaNm4vTn60njLtAQ7Q5oGsQILfA-5h9-sv4MBcVyNBAfSrUUajZqlUukT-5Bx8EqocSvf0RIFRHLcvO9_LMg"))
    //                        .build())
    //                .build();
    //        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";
    //
    //        when(proofValidationService.isProofValid(credentialRequest.proofs().jwt().get(0), token)).thenReturn(Mono.just(false));
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, token))
    //                .expectError(InvalidOrMissingProofException.class)
    //                .verify();
    //    }
    //
    //    @Test
    //    void generateVerifiableCredentialResponseInvalidSignerOrgIdentifier() {
    //        String processId = "1234";
    //        CredentialRequest credentialRequest = CredentialRequest.builder()
    //                .credentialConfigurationId(JWT_VC)
    //                .proofs(Proofs.builder()
    //                        .jwt(List.of("eyJraWQiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MjekRuYWVuMjN3TTc2Z3BpU0xIa3U0YkZEYnNzVlM5c3R5OXgzSzd5VnFqYlNkVFBXQyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjE3MTI5MTcwNDAsImlhdCI6MTcxMjA1MzA0MCwibm9uY2UiOiI4OVh4bXdMMlJtR2wyUlp1LU1UU3lRPT0ifQ.DdaaNm4vTn60njLtAQ7Q5oGsQILfA-5h9-sv4MBcVyNBAfSrUUajZqlUukT-5Bx8EqocSvf0RIFRHLcvO9_LMg"))
    //                        .build())
    //                .build();
    //        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";
    //        String jti = "fcca7591-6742-4c30-949c-ee9707196756";
    //        String did = "did:key:zDnaen23wM76gpiSLHku4bFDbssVS9sty9x3K7yVqjbSdTPWC";
    //        CredentialResponse credentialResponse = CredentialResponse.builder()
    //                .credentials(List.of(
    //                        CredentialResponse.Credential.builder()
    //                                .credential("credential")
    //                                .build()))
    //                .transactionId("4321")
    //                .build();
    //        String procedureId = "123456";
    //        String decodedCredential = "decodedCredential";
    //
    //        when(proofValidationService.isProofValid(credentialRequest.proofs().jwt().get(0), token)).thenReturn(Mono.just(true));
    //        when(verifiableCredentialService.buildCredentialResponse(processId, did, jti, token)).thenReturn(Mono.just(credentialResponse));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just(procedureId));
    //        when(deferredCredentialMetadataService.getOperationModeByAuthServerNonce(jti)).thenReturn(Mono.just("S"));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just("procedureId"));
    //        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId("procedureId")).thenReturn(Mono.empty());
    //        when(credentialProcedureService.getCredentialStatusByProcedureId("procedureId")).thenReturn(Mono.just(CredentialStatus.DRAFT.toString()));
    //        when(credentialProcedureService.getDecodedCredentialByProcedureId("procedureId")).thenReturn(Mono.just(decodedCredential));
    //
    //        LEARCredentialEmployee learCredentialEmployee = LEARCredentialEmployee.builder()
    //                .credentialSubject(
    //                        LEARCredentialEmployee.CredentialSubject.builder()
    //                                .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
    //                                        .mandator(Mandator.builder()
    //                                                .organizationIdentifier("")
    //                                                .build())
    //                                        .build()
    //                                )
    //                                .build()
    //                )
    //                .build();
    //
    //        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential)).thenReturn(learCredentialEmployee);
    //
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, token))
    //                .expectError(IllegalArgumentException.class)
    //                .verify();
    //    }
    //
    //    @Test
    //    void generateVerifiableCredentialResponseInvalidMandatorOrgIdentifier() {
    //        String processId = "1234";
    //        CredentialRequest credentialRequest = CredentialRequest.builder()
    //                .credentialConfigurationId(JWT_VC)
    //                .proofs(Proofs.builder()
    //                        .jwt(List.of("eyJraWQiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MjekRuYWVuMjN3TTc2Z3BpU0xIa3U0YkZEYnNzVlM5c3R5OXgzSzd5VnFqYlNkVFBXQyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjE3MTI5MTcwNDAsImlhdCI6MTcxMjA1MzA0MCwibm9uY2UiOiI4OVh4bXdMMlJtR2wyUlp1LU1UU3lRPT0ifQ.DdaaNm4vTn60njLtAQ7Q5oGsQILfA-5h9-sv4MBcVyNBAfSrUUajZqlUukT-5Bx8EqocSvf0RIFRHLcvO9_LMg"))
    //                        .build())
    //                .build();
    //        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";
    //        String jti = "fcca7591-6742-4c30-949c-ee9707196756";
    //        String did = "did:key:zDnaen23wM76gpiSLHku4bFDbssVS9sty9x3K7yVqjbSdTPWC";
    //        CredentialResponse credentialResponse = CredentialResponse.builder()
    //                .credentials(List.of(
    //                        CredentialResponse.Credential.builder()
    //                                .credential("credential")
    //                                .build()))
    //                .transactionId("4321")
    //                .build();
    //        String procedureId = "123456";
    //        String decodedCredential = "decodedCredential";
    //
    //        when(proofValidationService.isProofValid(credentialRequest.proofs().jwt().get(0), token)).thenReturn(Mono.just(true));
    //        when(verifiableCredentialService.buildCredentialResponse(processId, did, jti, token)).thenReturn(Mono.just(credentialResponse));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just(procedureId));
    //        when(deferredCredentialMetadataService.getOperationModeByAuthServerNonce(jti)).thenReturn(Mono.just("S"));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just("procedureId"));
    //        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId("procedureId")).thenReturn(Mono.empty());
    //        when(credentialProcedureService.getCredentialStatusByProcedureId("procedureId")).thenReturn(Mono.just(CredentialStatus.DRAFT.toString()));
    //        when(credentialProcedureService.getDecodedCredentialByProcedureId("procedureId")).thenReturn(Mono.just(decodedCredential));
    //
    //        LEARCredentialEmployee learCredentialEmployee = LEARCredentialEmployee.builder()
    //                .credentialSubject(
    //                        LEARCredentialEmployee.CredentialSubject.builder()
    //                                .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
    //                                        .signer(Signer.builder()
    //                                                .organizationIdentifier("some-identifier")
    //                                                .build())
    //                                        .mandator(Mandator.builder()
    //                                                .organizationIdentifier("")
    //                                                .build())
    //                                        .build()
    //                                )
    //                                .build()
    //                )
    //                .build();
    //
    //        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential)).thenReturn(learCredentialEmployee);
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, token))
    //                .expectError(IllegalArgumentException.class)
    //                .verify();
    //    }

    @Test
    void completeWithdrawLEARMachineProcessUsesOwnerEmailWhenProvided() throws Exception {
        // given
        String processId = "1234";
        String schema = "LEARCredentialMachine";
        String token = "token";
        String idToken = null;

        // owner email comes from the request and must take precedence over mandator.email
        String ownerEmail = "owner.override@in2.es";
        String mandatorEmail = "mandator@in2.es";
        String name = "Robot 3000";
        String org  = "IN2 Machines";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String issuerUiExternalDomain = "https://issuer.example.com";
        String transactionCode = "tx-ABCD";

        String json = """
    {
      "mandator": {
        "email": "%s",
        "commonName": "%s",
        "organization": "%s"
      }
    }
    """.formatted(mandatorEmail, name, org);

        ObjectMapper om = new ObjectMapper();
        JsonNode payload = om.readTree(json);

        PreSubmittedCredentialDataRequest req =
                PreSubmittedCredentialDataRequest.builder()
                        .payload(payload)
                        .schema(schema)
                        .format(JWT_VC_JSON)
                        .operationMode("S")
                        .credentialOwnerEmail(ownerEmail) // <- important for the test
                        .build();

        when(verifiableCredentialPolicyAuthorizationService.authorize(token, schema, payload, idToken))
                .thenReturn(Mono.empty());

        when(verifiableCredentialService.generateVc(processId, req, ownerEmail))
                .thenReturn(Mono.just(transactionCode));

        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);

        when(emailService.sendCredentialActivationEmail(
                ownerEmail,
                "Activate your new credential",
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
                knowledgebaseWalletUrl,
                org
        )).thenReturn(Mono.empty());

        // when / then
        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, req, token, idToken))
                .verifyComplete();

        // and we explicitly verify that ownerEmail was used
        verify(emailService).sendCredentialActivationEmail(
                eq(ownerEmail),
                anyString(),
                contains(transactionCode),
                eq(knowledgebaseWalletUrl),
                eq(org)
        );
    }

    @Test
    void generateVerifiableCredentialResponse_PersistsEncodedAndFormat_AfterBuild() {
        // given
        String processId = "proc-1";
        String nonce = "nonce-save-001";
        String token = buildDummyJwtWithJti(nonce);

        // metadata so it does NOT require a proof (thus subject DID = null and direct path)
        CredentialIssuerMetadata metadata = mock(CredentialIssuerMetadata.class);
        CredentialIssuerMetadata.CredentialConfiguration cfg =
                mock(CredentialIssuerMetadata.CredentialConfiguration.class);
        CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition def =
                mock(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.class);

        String typeId = CredentialType.LEAR_CREDENTIAL_MACHINE.getTypeId();
        when(cfg.credentialDefinition()).thenReturn(def);
        when(def.type()).thenReturn(Set.of(typeId));
        when(cfg.cryptographicBindingMethodsSupported()).thenReturn(Collections.emptySet());
        Map<String, CredentialIssuerMetadata.CredentialConfiguration> map = new HashMap<>();
        map.put("cfg1", cfg);
        when(metadata.credentialConfigurationsSupported()).thenReturn(map);

        // deferred with procedureId and without responseUri (no delivery needed)
        String procedureId = "save-me";
        DeferredCredentialMetadata deferred = mock(DeferredCredentialMetadata.class);
        when(deferred.getProcedureId()).thenReturn(java.util.UUID.randomUUID());
        when(deferred.getResponseUri()).thenReturn(null);

        // procedure mock
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getOperationMode()).thenReturn("S"); // SYNC
        when(proc.getCredentialType()).thenReturn(CredentialType.LEAR_CREDENTIAL_MACHINE.name());

        // services: fetch deferred + procedure + metadata
        when(deferredCredentialMetadataService.getDeferredCredentialMetadataByAuthServerNonce(nonce))
                .thenReturn(Mono.just(deferred));
        when(credentialProcedureService.getCredentialProcedureById(anyString()))
                .thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(processId))
                .thenReturn(Mono.just(metadata));

        // VC response that MUST be PERSISTED (encoded + format)
        String encodedJwt = "eyJhbGciOiJ...encoded.jwt...";
        CredentialResponse cr = CredentialResponse.builder()
                .credentials(List.of(CredentialResponse.Credential.builder().credential(encodedJwt).build()))
                .transactionId("t-encoded")
                .build();

        when(verifiableCredentialService.buildCredentialResponse(eq(processId), isNull(), eq(nonce), eq(token)))
                .thenReturn(Mono.just(cr));

        // the implementation stores using nonce -> procedureId
        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(nonce))
                .thenReturn(Mono.just(procedureId));

        // in SYNC it updates status (if not PEND_SIGNATURE) and reads decoded (no impact)
        when(credentialProcedureService.getCredentialStatusByProcedureId(procedureId))
                .thenReturn(Mono.just(CredentialStatusEnum.DRAFT.toString()));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
                .thenReturn(Mono.just("{\"vc\":\"decoded\"}"));


        // when
        StepVerifier.create(
                        verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(
                                processId,
                                CredentialRequest.builder().credentialConfigurationId(JWT_VC_JSON).build(),
                                token
                        )
                )
                .expectNext(cr)
                .verifyComplete();

        // and it was NOT attempted to be sent (no responseUri)
        verifyNoInteractions(credentialDeliveryService);
    }


    @Test
    void generateVerifiableCredentialResponse_UsesEncodedCredentialOnDelivery() {
        // --- Minimal setup so the flow reaches the send to responseUri with ENCODED ---
        String processId = "p-1";
        String nonce = "nonce123";
        String token = buildDummyJwtWithJti(nonce); // simple compact JWS that Nimbus can parse

        // Deferred -> points to our procedureId and has a responseUri
        String procedureId = "proc-99";
        String responseUri = "https://wallet.example.com/callback";

        // CredentialProcedure mock
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getOperationMode()).thenReturn("S"); // SYNC
        when(proc.getCredentialType()).thenReturn(CredentialType.LEAR_CREDENTIAL_MACHINE.name());
        when(proc.getOwnerEmail()).thenReturn("owner@in2.es");
        when(proc.getCredentialEncoded()).thenReturn("ENCODED_JWT_VALUE"); // <- what we want to be sent

        // Deferred metadata mock
        DeferredCredentialMetadata deferred = mock(DeferredCredentialMetadata.class);
        when(deferred.getProcedureId()).thenReturn(java.util.UUID.randomUUID());
        when(deferred.getResponseUri()).thenReturn(responseUri);

        // ---- Metadata mock configuration without deep stubs ----
        CredentialIssuerMetadata metadata = mock(CredentialIssuerMetadata.class);

        // Note: it's a final record; this requires mock-maker-inline.
        // If you don't have it, see the "without mocks" alternative below.
        CredentialIssuerMetadata.CredentialConfiguration cfg =
                mock(CredentialIssuerMetadata.CredentialConfiguration.class);

        CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition def =
                mock(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.class);

        String typeId = CredentialType.LEAR_CREDENTIAL_MACHINE.getTypeId();

        // return value of credentialDefinition()
        when(cfg.credentialDefinition()).thenReturn(def);

        // type() returns Set<String>
        when(def.type()).thenReturn(Set.of(typeId));

        // cryptographicBindingMethodsSupported() returns Set<String>
        when(cfg.cryptographicBindingMethodsSupported()).thenReturn(Collections.emptySet());

        // map of configs
        Map<String, CredentialIssuerMetadata.CredentialConfiguration> map = new HashMap<>();
        map.put("cfg1", cfg);
        when(metadata.credentialConfigurationsSupported()).thenReturn(map);
        // ---- end of configuration ----


        // Service chains
        when(deferredCredentialMetadataService.getDeferredCredentialMetadataByAuthServerNonce(nonce))
                .thenReturn(Mono.just(deferred));

        when(credentialProcedureService.getCredentialProcedureById(anyString()))
                .thenReturn(Mono.just(proc));

        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(processId))
                .thenReturn(Mono.just(metadata));

        // buildCredentialResponse doesn't need a subject DID (config without proof), it will go through the null branch
        CredentialResponse cr = CredentialResponse.builder()
                .credentials(List.of(CredentialResponse.Credential.builder().credential("whatever").build()))
                .transactionId("t-1")
                .build();
        when(verifiableCredentialService.buildCredentialResponse(eq(processId), isNull(), eq(nonce), eq(token)))
                .thenReturn(Mono.just(cr));

        // In SYNC: status and decoded are queried (the decoded is not used unless it's employee)
        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(nonce))
                .thenReturn(Mono.just(procedureId));

        when(credentialProcedureService.getCredentialStatusByProcedureId(procedureId))
                .thenReturn(Mono.just(CredentialStatusEnum.DRAFT.toString()));

        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());

        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
                .thenReturn(Mono.just("DECODED_SHOULD_NOT_BE_USED"));

        // getCredentialId for sending
        when(credentialProcedureService.getCredentialId(proc)).thenReturn(Mono.just("cred-777"));

        // M2M token for sending
        when(m2MTokenService.getM2MToken())
                .thenReturn(Mono.just(new VerifierOauth2AccessToken("access-token-value", "", "")));

        // capture the parameters passed to the send call
        ArgumentCaptor<String> responseUriCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> encodedCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> credIdCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> ownerEmailCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> accessTokenCap = ArgumentCaptor.forClass(String.class);

        when(credentialDeliveryService.sendVcToResponseUri(
                responseUriCap.capture(),
                encodedCap.capture(),
                credIdCap.capture(),
                ownerEmailCap.capture(),
                accessTokenCap.capture()
        )).thenReturn(Mono.empty());

        // when
        StepVerifier.create(
                        verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId,
                                CredentialRequest.builder()
                                        .credentialConfigurationId(JWT_VC_JSON)
                                        .build(),
                                token)
                )
                .expectNext(cr)
                .verifyComplete();

        // then: the ENCODED was used (not the decoded)
        assert responseUriCap.getValue().equals(responseUri);
        assert encodedCap.getValue().equals("ENCODED_JWT_VALUE");
        assert credIdCap.getValue().equals("cred-777");
        assert ownerEmailCap.getValue().equals("owner@in2.es");
        assert accessTokenCap.getValue().equals("access-token-value");
    }

    /** Helper: minimal compact JWT with "jti" in the payload that Nimbus can parse without validating the signature */
    private static String buildDummyJwtWithJti(String jti) {
        String h = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String p = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"jti\":\"" + jti + "\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        // dummy signature
        String s = "sig";
        return h + "." + p + "." + s;
    }



    @Test
    void bindAccessTokenByPreAuthorizedCodeSuccess() {
        String processId = "1234";
        AuthServerNonceRequest authServerNonceRequest = AuthServerNonceRequest.builder()
                .accessToken("ey1234")
                .preAuthorizedCode("4321")
                .build();

        when(verifiableCredentialService.bindAccessTokenByPreAuthorizedCode(processId, authServerNonceRequest.accessToken(), authServerNonceRequest.preAuthorizedCode()))
                .thenReturn(Mono.empty());
        StepVerifier.create(verifiableCredentialIssuanceWorkflow.bindAccessTokenByPreAuthorizedCode(processId, authServerNonceRequest))
                .verifyComplete();
    }

    @Test
    void completeWithdrawLEARMachineProcessSyncSuccess() throws Exception {
        String processId = "1234";
        String type = "LEARCredentialMachine";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String issuerUiExternalDomain = "https://example.com";
        String token = "token";
        String idToken = null;
        String expectedEmail = "machine.owner@in2.es";
        String expectedOrg   = "IN2 Machines";

        String json = """
        {
          "mandator": {
            "email": "machine.owner@in2.es",
            "commonName": "Robot 3000",
            "organization": "IN2 Machines"
          }
        }
        """;

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(json);

        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest =
                PreSubmittedCredentialDataRequest.builder()
                        .payload(jsonNode)
                        .schema("LEARCredentialMachine")
                        .format(JWT_VC_JSON)
                        .operationMode("S")
                        .build();

        String transactionCode = "tx-9876";

        // arrange
        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, idToken))
                .thenReturn(Mono.empty());

        when(verifiableCredentialService.generateVc(processId, preSubmittedCredentialDataRequest, expectedEmail))
                .thenReturn(Mono.just(transactionCode));

        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);


        when(emailService.sendCredentialActivationEmail(
                expectedEmail,
                "Activate your new credential",
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
                knowledgebaseWalletUrl,
                expectedOrg
        )).thenReturn(Mono.empty());

        StepVerifier.create(
                verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, token, idToken)
        ).verifyComplete();
    }


}
