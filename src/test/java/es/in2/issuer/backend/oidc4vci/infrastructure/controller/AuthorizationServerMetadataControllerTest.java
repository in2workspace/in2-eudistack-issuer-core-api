package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.GetAuthorizationServerMetadataWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationServerMetadata;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.Set;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(AuthorizationServerMetadataController.class)
class AuthorizationServerMetadataControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @MockBean
    private GetAuthorizationServerMetadataWorkflow getAuthorizationServerMetadataWorkflow;

    @Test
    void testGetAuthorizationServerMetadataSuccess() {
        // Arrange
        AuthorizationServerMetadata expectedAuthorizationServerMetadata = AuthorizationServerMetadata.builder()
                .issuer("https://issuer.example.com")
                .tokenEndpoint("https://issuer.example.com/oauth/token")
                .responseTypesSupported(Set.of("token"))
                .preAuthorizedGrantAnonymousAccessSupported(true)
                .build();
        // Mock
        when(getAuthorizationServerMetadataWorkflow.execute(anyString()))
                .thenReturn(Mono.just(expectedAuthorizationServerMetadata));
        // Act + Assert
        webTestClient
                .get()
                .uri("/.well-known/openid-configuration")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.CONTENT_LANGUAGE, "en")
                .expectBody(AuthorizationServerMetadata.class)
                .isEqualTo(expectedAuthorizationServerMetadata);
    }

}
