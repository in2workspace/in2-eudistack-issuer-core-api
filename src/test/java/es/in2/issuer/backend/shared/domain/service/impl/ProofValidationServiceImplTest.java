package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.application.workflow.NonceValidationWorkflow;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ProofValidationServiceImplTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private NonceValidationWorkflow nonceValidationWorkflow;

    @InjectMocks
    private ProofValidationServiceImpl service;

    @Test
    void isProofValid_valid() {
        String validProof = "eyJraWQiOiJkaWQ6a2V5OnpEbmFlbURadmk2UFdMbjRLRjY2NlJzZ3ZTSnR5R1B4V05GQW8xenZNSmliTGFCSHYjekRuYWVtRFp2aTZQV0xuNEtGNjY2UnNndlNKdHlHUHhXTkZBbzF6dk1KaWJMYUJIdiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbURadmk2UFdMbjRLRjY2NlJzZ3ZTSnR5R1B4V05GQW8xenZNSmliTGFCSHYiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjMzMjE3NjMwOTgzLCJpYXQiOjE3MTMxNjY5ODMsIm5vbmNlIjoiLVNReklWbWxRTUNWd2xRak53SnRRUT09In0.hgLg04YCmEMa30JQYTZSz3vEGxTfBNYdx3A3wSNrtuJcb9p-96MtPCmLTpIFBU_CLTI4Wm4_lc-rbRMitIiOxA";
        String token = "token";

        when(jwtService.validateJwtSignatureReactive(any())).thenReturn(Mono.just(true));

        Mono<Boolean> result = service.isProofValid(validProof, token);
        // Verify the output
        StepVerifier.create(result)
                .assertNext(response ->
                        assertTrue(response, "The response is wrong"))
                .verifyComplete();
    }
}