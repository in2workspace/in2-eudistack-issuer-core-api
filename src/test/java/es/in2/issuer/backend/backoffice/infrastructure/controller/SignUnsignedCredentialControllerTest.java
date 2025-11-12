package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
        SignUnsignedCredentialController controller =
                new SignUnsignedCredentialController(credentialSignerWorkflow, accessTokenService);
        webTestClient = WebTestClient.bindToController(controller).build();
    }

    @Test
    void signUnsignedCredential_success() {
        // given
        String authorizationHeader = "Bearer token";
        String token = "token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
        String email = "alice@example.com";
        String organizationId = "org-123";

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));
        when(credentialSignerWorkflow.retrySignUnsignedCredential(token, procedureId, email, organizationId))
                .thenReturn(Mono.empty());

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().isCreated();

        // Verify all AccessTokenService methods were called (order doesn't matter with Mono.zip)
        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(accessTokenService).getMandateeEmail(authorizationHeader);
        verify(accessTokenService).getOrganizationId(authorizationHeader);
        verify(credentialSignerWorkflow)
                .retrySignUnsignedCredential(token, procedureId, email, organizationId);
        verifyNoMoreInteractions(accessTokenService, credentialSignerWorkflow);
    }

    @Test
    void signUnsignedCredential_workflowError_propagates5xx() {
        // given
        String authorizationHeader = "Bearer token";
        String token = "token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
        String email = "alice@example.com";
        String organizationId = "org-123";

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just(organizationId));
        when(credentialSignerWorkflow.retrySignUnsignedCredential(token, procedureId, email, organizationId))
                .thenReturn(Mono.error(new RuntimeException("Simulated error")));

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().is5xxServerError();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(accessTokenService).getMandateeEmail(authorizationHeader);
        verify(accessTokenService).getOrganizationId(authorizationHeader);
        verify(credentialSignerWorkflow)
                .retrySignUnsignedCredential(token, procedureId, email, organizationId);
        verifyNoMoreInteractions(accessTokenService, credentialSignerWorkflow);
    }

    @Test
    void signUnsignedCredential_accessTokenError_propagates5xx_andWorkflowNotCalled() {
        // given
        String authorizationHeader = "Bearer token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";

        // Error happens while extracting/cleaning the token from the header
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.error(new IllegalArgumentException("Bad header")));
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just("alice@example.com"));
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just("org-123"));

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().is5xxServerError();

        // All three AccessTokenService methods are called in parallel due to Mono.zip
        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(accessTokenService).getMandateeEmail(authorizationHeader);
        verify(accessTokenService).getOrganizationId(authorizationHeader);
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
                .expectStatus().isBadRequest();

        verifyNoInteractions(accessTokenService, credentialSignerWorkflow);
    }

    @Test
    void signUnsignedCredential_emptyEmail_failsZip_andWorkflowNotCalled() {
        // given
        String authorizationHeader = "Bearer token";
        String token = "token";
        String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";

        // With Mono.zip, if any of the sources is empty, the zip fails and flatMap is not executed
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.empty());
        when(accessTokenService.getOrganizationId(authorizationHeader))
                .thenReturn(Mono.just("org-123"));

        // when + then
        webTestClient.post()
                .uri("/backoffice/v1/retry-sign-credential/" + procedureId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .exchange()
                .expectStatus().isCreated(); // Completes with 201 but no body

        // All three methods are called due to Mono.zip
        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(accessTokenService).getMandateeEmail(authorizationHeader);
        verify(accessTokenService).getOrganizationId(authorizationHeader);
        verifyNoInteractions(credentialSignerWorkflow);
        verifyNoMoreInteractions(accessTokenService);
    }
}