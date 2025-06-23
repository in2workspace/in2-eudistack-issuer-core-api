package es.in2.issuer.backend.backoffice.infrastructure.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(IssuanceController.class)
class IssuanceControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private CredentialIssuanceWorkflow credentialIssuanceWorkflow;

    @MockBean
    private AccessTokenService accessTokenService;

    @ParameterizedTest
    @ValueSource(strings = {"/backoffice/v1/issuances", "/vci/v1/issuances"})
    void issueCredential_Success(String uri) throws JsonProcessingException {

        String bearerToken = "Bearer test-token";
        String cleanToken = "test-token";
        var testRequest = PreSubmittedCredentialDataRequest.builder()
                .schema("test-schema")
                .format("test-format")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .build();

        when(accessTokenService.getCleanBearerToken(bearerToken))
                .thenReturn(Mono.just(cleanToken));
        when(credentialIssuanceWorkflow.execute(anyString(), eq(testRequest), eq(cleanToken), isNull()))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .post()
                .uri(uri)
                .header(HttpHeaders.AUTHORIZATION, bearerToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(testRequest))
                .exchange()
                .expectStatus().isCreated()
                .expectBody().isEmpty();
    }
}