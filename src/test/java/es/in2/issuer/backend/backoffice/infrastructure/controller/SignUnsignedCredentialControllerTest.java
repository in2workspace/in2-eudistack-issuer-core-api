package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SignUnsignedCredentialControllerTest {

    @Mock
    private CredentialSignerWorkflow credentialSignerWorkflow;

    @Mock
    private AccessTokenService accessTokenService;

    private WebTestClient webTestClient;

    @BeforeEach
    void setup() {
        // Bind controller with BOTH dependencies mocked
        SignUnsignedCredentialController controller =
                new SignUnsignedCredentialController(credentialSignerWorkflow, accessTokenService);
        webTestClient = WebTestClient.bindToController(controller).build();
    }

    @Test
    void signUnsignedCredential_success() {
        // given
        String authorizationHeader = "Bearer token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
        String email = "alice@example.com";

        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId, email))
                .thenReturn(Mono.empty());

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().isCreated();

        // Verify call order and arguments
        InOrder inOrder = inOrder(accessTokenService, credentialSignerWorkflow);
        inOrder.verify(accessTokenService).getMandateeEmail(authorizationHeader);
        inOrder.verify(credentialSignerWorkflow)
                .retrySignUnsignedCredential(authorizationHeader, procedureId, email);
        verifyNoMoreInteractions(accessTokenService, credentialSignerWorkflow);
    }

    @Test
    void signUnsignedCredential_workflowError_propagates5xx() {
        // given
        String authorizationHeader = "Bearer token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
        String email = "alice@example.com";

        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialSignerWorkflow.retrySignUnsignedCredential(authorizationHeader, procedureId, email))
                .thenReturn(Mono.error(new RuntimeException("Simulated error")));

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().is5xxServerError();

        verify(accessTokenService, times(1)).getMandateeEmail(authorizationHeader);
        verify(credentialSignerWorkflow, times(1))
                .retrySignUnsignedCredential(authorizationHeader, procedureId, email);
        verifyNoMoreInteractions(accessTokenService, credentialSignerWorkflow);
    }

    @Test
    void signUnsignedCredential_accessTokenError_propagates5xx_andWorkflowNotCalled() {
        // given
        String authorizationHeader = "Bearer token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";

        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.error(new IllegalArgumentException("Bad token")));

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().is5xxServerError();

        verify(accessTokenService, times(1)).getMandateeEmail(authorizationHeader);
        verifyNoInteractions(credentialSignerWorkflow);
        verifyNoMoreInteractions(accessTokenService);
    }

    @Test
    void signUnsignedCredential_missingAuthorizationHeader_returns400_andNoCalls() {
        // given
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .exchange()
                .expectStatus().isBadRequest(); // missing required header → 400

        verifyNoInteractions(accessTokenService, credentialSignerWorkflow);
    }

    @Test
    void signUnsignedCredential_emptyEmail_completes201_andWorkflowNotCalled() {
        // given
        String authorizationHeader = "Bearer token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";

        // If the token service returns empty, the flatMap is never executed and the endpoint completes.
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.empty());

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().isCreated();

        verify(accessTokenService, times(1)).getMandateeEmail(authorizationHeader);
        verifyNoInteractions(credentialSignerWorkflow);
        verifyNoMoreInteractions(accessTokenService);
    }
}
