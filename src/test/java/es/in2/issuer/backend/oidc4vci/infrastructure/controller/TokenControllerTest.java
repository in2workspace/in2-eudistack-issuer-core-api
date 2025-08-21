package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(TokenController.class)
class TokenControllerTest {

    @MockBean
    TokenService tokenService;

    @Autowired
    WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @Test
    void testGetEntitiesSuccess() {
        String grantType = GRANT_TYPE;
        String preAuthorizedCode = "5678";
        String txCode = "9012";
        TokenResponse tokenResponse = new TokenResponse(
                "access-token",
                "token-type",
                3600L,
                "null");
        when(tokenService.generateTokenResponse(
                grantType,
                preAuthorizedCode,
                txCode))
                .thenReturn(Mono.just(tokenResponse));

        webTestClient
                .mutateWith(csrf())
                .post()
                .uri("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters
                        .fromFormData("grant_type", grantType)
                        .with("pre-authorized_code", preAuthorizedCode)
                        .with("tx_code", txCode))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(TokenResponse.class)
                .isEqualTo(tokenResponse);
    }
}