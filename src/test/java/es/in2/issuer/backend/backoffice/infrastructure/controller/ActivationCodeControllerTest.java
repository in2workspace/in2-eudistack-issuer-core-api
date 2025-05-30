package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ActivationCodeControllerTest {

    @Mock
    private ActivationCodeWorkflow activationCodeWorkflow;

    @InjectMocks
    private ActivationCodeController activationCodeController;

    @Test
    void getCredentialOfferByTransactionCode() {
        //Arrange
        String transactionCode = "testTransactionCode";
        String credentialOfferUri = "https://www.goodair.com/credential-offer?credential_offer_uri=https://www.goodair.com/credential-offer/5j349k3e3n23j";
        String cTransactionCode = "testCTransactionCode";
        CredentialOfferUriResponse credentialOfferUriResponse = CredentialOfferUriResponse.builder()
                .cTransactionCode(cTransactionCode)
                .credentialOfferUri(credentialOfferUri)
                .build();
        when(activationCodeWorkflow.buildCredentialOfferUri(anyString(), eq(transactionCode))).thenReturn(Mono.just(credentialOfferUriResponse));
        //Act
        Mono<CredentialOfferUriResponse> result = activationCodeController.getCredentialOfferByTransactionCode(transactionCode);
        //Assert
        StepVerifier.create(result)
                .assertNext(credentialOfferUriResponse1 -> assertEquals(credentialOfferUriResponse, credentialOfferUriResponse1))
                .verifyComplete();
    }

    @Test
    void getNewCredentialOfferByTransactionCode() {
        //Arrange
        String transactionCode = "testTransactionCode";
        String credentialOfferUri = "https://www.goodair.com/credential-offer?credential_offer_uri=https://www.goodair.com/credential-offer/5j349k3e3n23j";
        String cTransactionCode = "testCTransactionCode";
        CredentialOfferUriResponse credentialOfferUriResponse = CredentialOfferUriResponse.builder()
                .cTransactionCode(cTransactionCode)
                .credentialOfferUri(credentialOfferUri)
                .build();
        when(activationCodeWorkflow.buildNewCredentialOfferUri(anyString(), eq(transactionCode))).thenReturn(Mono.just(credentialOfferUriResponse));
        //Act
        Mono<CredentialOfferUriResponse> result = activationCodeController.getCredentialOfferByCTransactionCode(transactionCode);
        //Assert
        StepVerifier.create(result)
                .assertNext(credentialOfferUriResponse1 -> assertEquals(credentialOfferUriResponse, credentialOfferUriResponse1))
                .verifyComplete();
    }

}
