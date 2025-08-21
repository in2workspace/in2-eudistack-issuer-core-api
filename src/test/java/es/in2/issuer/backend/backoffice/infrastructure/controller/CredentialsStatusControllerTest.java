package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.application.workflow.CredentialStatusWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialStatusResponse;
import es.in2.issuer.backend.backoffice.domain.model.dtos.RevokeCredentialRequest;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(CredentialStatusController.class)
class CredentialsStatusControllerTest {

    private static final String BASE_URI = "/backoffice/v1/credentials/status";

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @MockBean
    private CredentialStatusWorkflow credentialStatusWorkflow;

    @Test
    void getCredentialsStatus_Success() {
        List<String> mockStatusList = List.of(
                "1b59b5f8-a66b-4694-af47-cf38db7a3d73",
                "c046b54b-aa8a-4c8d-af2b-a3d60a61b80b");

        int listId = 1;
        when(credentialStatusWorkflow.getCredentialsByListId(anyString(), eq(listId)))
                .thenReturn(Flux.fromIterable(mockStatusList));

        List<CredentialStatusResponse> expectedResponse = mockStatusList.stream()
                .map(CredentialStatusResponse::new)
                .toList();

        webTestClient.get()
                .uri(BASE_URI + "/{list-id}", listId)
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(CredentialStatusResponse.class)
                .isEqualTo(expectedResponse);
    }

    @Test
    void revokeCredential_Success() {
        RevokeCredentialRequest request = new RevokeCredentialRequest("1b59b5f8-a66b-4694-af47-cf38db7a3d73", 1);

        String bearerToken = "Bearer mock-token";

        when(credentialStatusWorkflow.revokeCredential(
                anyString(),
                eq(bearerToken),
                eq(request.credentialId()),
                eq(request.listId())))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .post()
                .uri(BASE_URI + "/revoke")
                .header("Authorization", bearerToken)
                .bodyValue(request)
                .exchange()
                .expectStatus().isCreated();
    }
}