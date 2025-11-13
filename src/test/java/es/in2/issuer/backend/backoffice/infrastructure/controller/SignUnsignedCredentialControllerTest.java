package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SignUnsignedCredentialControllerTest {

    @Mock
    private CredentialSignerWorkflow credentialSignerWorkflow;

    private WebTestClient webTestClient;

    @BeforeEach
    void setup() {
        SignUnsignedCredentialController controller =
                new SignUnsignedCredentialController(credentialSignerWorkflow);
        webTestClient = WebTestClient.bindToController(controller).build();
    }

    @Test
    void signUnsignedCredential_success() {
        // given
        String authorizationHeader = "Bearer token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";

        when(credentialSignerWorkflow.retrySignUnsignedCredential(
                anyString(), eq(authorizationHeader), eq(procedureId)))
                .thenReturn(Mono.empty());

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().isCreated();

        // processId és aleatori, així que només comprovem que s’hi passa algun String
        verify(credentialSignerWorkflow)
                .retrySignUnsignedCredential(anyString(), eq(authorizationHeader), eq(procedureId));
        verifyNoMoreInteractions(credentialSignerWorkflow);
    }

    @Test
    void signUnsignedCredential_workflowError_propagates5xx() {
        // given
        String authorizationHeader = "Bearer token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";

        when(credentialSignerWorkflow.retrySignUnsignedCredential(
                anyString(), eq(authorizationHeader), eq(procedureId)))
                .thenReturn(Mono.error(new RuntimeException("Simulated error")));

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().is5xxServerError();

        verify(credentialSignerWorkflow)
                .retrySignUnsignedCredential(anyString(), eq(authorizationHeader), eq(procedureId));
        verifyNoMoreInteractions(credentialSignerWorkflow);
    }

    @Test
    void signUnsignedCredential_missingAuthorizationHeader_returns400_andNoCalls() {
        // given
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .exchange()
                .expectStatus().isBadRequest();

        verifyNoInteractions(credentialSignerWorkflow);
    }
}
