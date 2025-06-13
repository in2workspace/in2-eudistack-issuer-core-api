package es.in2.issuer.backend.backoffice.infrastructure.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.CredentialConfigurationsSupported;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedDataCredentialRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.io.IOException;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SYNC;
import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(IssuanceController.class)
class IssuanceControllerTest {

    @MockBean
    private CredentialIssuanceWorkflow credentialIssuanceWorkflow;

    @Autowired
    private WebTestClient webTestClient;

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void internalIssueCredential_ValidRequest_ReturnsCreated() throws IOException {
        PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest =
                PreSubmittedDataCredentialRequest.builder()
                        .schema(CredentialConfigurationsSupported.LEAR_CREDENTIAL_EMPLOYEE.toString())
                        .format(JWT_VC_JSON)
                        .payload(mapper.readTree("{\"key\": \"value\"}"))
                        .operationMode(SYNC)
                        .validityPeriod(1)
                        .responseUri("")
                        .build();
        webTestClient
                .mutateWith(csrf())
                .post()
                .uri("/backoffice/v1/issuances")
                .header("Authorization", "Bearer eyJ...")
                .body(Mono.just(preSubmittedDataCredentialRequest), PreSubmittedDataCredentialRequest.class)
                .exchange()
                .expectStatus().isCreated();
    }

    @Test
    void externalIssueCredential_ValidRequest_ReturnsCreated() throws IOException {
        PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest =
                PreSubmittedDataCredentialRequest.builder()
                        .schema(CredentialConfigurationsSupported.LEAR_CREDENTIAL_EMPLOYEE.toString())
                        .format(JWT_VC_JSON)
                        .payload(mapper.readTree("{\"key\": \"value\"}"))
                        .operationMode(SYNC)
                        .validityPeriod(1)
                        .responseUri("")
                        .build();
        webTestClient
                .mutateWith(csrf())
                .post()
                .uri("/vci/v1/issuances")
                .header("Authorization", "Bearer eyJ...")
                .body(Mono.just(preSubmittedDataCredentialRequest), PreSubmittedDataCredentialRequest.class)
                .exchange()
                .expectStatus().isCreated();
    }

    @Test
    void internalIssueCredential_InvalidPreSubmittedCredential_ReturnsBadRequest() throws IOException {
        PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest =
                PreSubmittedDataCredentialRequest.builder()
                        .schema("Invalid schema")
                        .format(JWT_VC_JSON)
                        .payload(mapper.readTree("{\"key\": \"value\"}"))
                        .operationMode(SYNC)
                        .validityPeriod(1)
                        .responseUri("")
                        .build();
        webTestClient
                .mutateWith(csrf())
                .post()
                .uri("/backoffice/v1/issuances")
                .header("Authorization", "Bearer eyJ...")
                .body(Mono.just(preSubmittedDataCredentialRequest), PreSubmittedDataCredentialRequest.class)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void externalIssueCredential_InvalidRequest_ReturnsBadRequest() throws IOException {
        PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest =
                PreSubmittedDataCredentialRequest.builder()
                        .schema("invalid_schema")
                        .format(JWT_VC_JSON)
                        .payload(mapper.readTree("{\"key\": \"value\"}"))
                        .operationMode(SYNC)
                        .validityPeriod(1)
                        .responseUri("")
                        .build();
        webTestClient
                .mutateWith(csrf())
                .post()
                .uri("/vci/v1/issuances")
                .header("Authorization", "Bearer eyJ...")
                .body(Mono.just(preSubmittedDataCredentialRequest), PreSubmittedDataCredentialRequest.class)
                .exchange()
                .expectStatus().isBadRequest();
    }
}