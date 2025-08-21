package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.GetCredentialIssuerMetadataWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Set;

import static org.mockito.Mockito.*;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(CredentialIssuerMetadataController.class)
class CredentialIssuerMetadataControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @MockBean
    private GetCredentialIssuerMetadataWorkflow getCredentialIssuerMetadataWorkflow;

    @Test
    void testGetCredentialIssuer_Metadata_Success() {
        // Arrange
        CredentialIssuerMetadata expectedCredentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("https://issuer.example.com")
                .issuanceEndpoint("https://issuer.example.com/vci/v1/issuances")
                .credentialEndpoint("https://issuer.example.com/oid4vci/v1/credential")
                .deferredCredentialEndpoint("https://issuer.example.com/oid4vci/v1/deferred-credential")
                .credentialConfigurationsSupported(Map.of(
                        "LEARCredentialEmployee", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("lear_credential_employee")
                                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .credentialDefinition(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                                        .type(Set.of("VerifiableCredential", "LEARCredentialEmployee"))
                                        .build())
                                .proofTypesSupported(Map.of("jwt", CredentialIssuerMetadata.CredentialConfiguration.ProofSigninAlgValuesSupported.builder()
                                        .proofSigningAlgValuesSupported(Set.of("ES256"))
                                        .build()))
                                .build(),
                        "LEARCredentialMachine", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("lear_credential_machine")
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .credentialDefinition(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                                        .type(Set.of("VerifiableCredential", "LEARCredentialMachine"))
                                        .build())
                                .build(),
                        "VerifiableCertification", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("verifiable_certification")
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .credentialDefinition(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                                        .type(Set.of("VerifiableCredential", "VerifiableCertification"))
                                        .build())
                                .build()
                ))
                .build();
        //Mock
        when(getCredentialIssuerMetadataWorkflow.execute(anyString()))
                .thenReturn(Mono.just(expectedCredentialIssuerMetadata));
        ServerWebExchange mockExchange = mock(ServerWebExchange.class);
        ServerHttpResponse mockResponse = mock(ServerHttpResponse.class);
        when(mockExchange.getResponse()).thenReturn(mockResponse);
        HttpHeaders mockHeaders = new HttpHeaders();
        when(mockResponse.getHeaders()).thenReturn(mockHeaders);
        // Act
        webTestClient
                .get()
                .uri("/.well-known/openid-credential-issuer")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.CONTENT_LANGUAGE, "en")
                .expectBody(CredentialIssuerMetadata.class)
                .isEqualTo(expectedCredentialIssuerMetadata);
    }

}
