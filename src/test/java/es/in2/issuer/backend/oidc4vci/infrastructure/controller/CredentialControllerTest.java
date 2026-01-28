package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialControllerTest {

    @Mock
    private CredentialIssuanceWorkflow credentialIssuanceWorkflow;

    @Mock
    private AccessTokenService accessTokenService;

    @InjectMocks
    private CredentialController credentialController;

    @Test
    void createVerifiableCredential() {
        //Arrange
        String authorizationHeader = "Bearer testToken";
        CredentialRequest credentialRequest = CredentialRequest.builder()
                .credentialConfigurationId("sampleFormat")
                .build();
        CredentialResponse credentialResponse = CredentialResponse.builder()
                .credentials(List.of(
                        CredentialResponse.Credential.builder()
                                .credential("sampleCredential")
                                .build()))
                .transactionId("sampleTransactionId")
                .build();
        ResponseEntity<CredentialResponse> expectedResponse = new ResponseEntity<>(credentialResponse, HttpStatus.ACCEPTED);
        when(accessTokenService.getCleanBearerToken(authorizationHeader)).thenReturn(Mono.just("testToken"));
        when(credentialIssuanceWorkflow.generateVerifiableCredentialResponse(anyString(), eq(credentialRequest), anyString())).thenReturn(Mono.just(credentialResponse));

        Mono<ResponseEntity<CredentialResponse>> result = credentialController.createVerifiableCredential(authorizationHeader, credentialRequest);

        StepVerifier.create(result)
                .assertNext(response -> assertEquals(expectedResponse, response))
                .verifyComplete();
    }

}