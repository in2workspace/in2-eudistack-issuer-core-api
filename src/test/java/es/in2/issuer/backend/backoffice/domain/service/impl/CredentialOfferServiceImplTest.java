package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;

    @BeforeEach
    void setUp() {
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://example.com");
    }

    @Test
    void testBuildCustomCredentialOffer() {
        String credentialType = "type1";
        String preAuthCode = "code123";
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://example.com");
        StepVerifier.create(credentialOfferService.buildCustomCredentialOffer(credentialType, preAuthCode))
                .expectNextMatches(offer ->
                        offer.credentialIssuer().equals("https://example.com") &&
                                offer.credentialConfigurationIds().equals(List.of(LEAR_CREDENTIAL_EMPLOYEE)) &&
                                offer.grants().containsKey(GRANT_TYPE) &&
                                offer.grants().get(GRANT_TYPE).preAuthorizedCode().equals(preAuthCode) &&
                                offer.grants().get(GRANT_TYPE).txCode().length() == 4
                )
                .verifyComplete();
    }

    @Test
    void testCreateCredentialOfferUriResponse() {
        String nonce = "abc123";
        Mono<String> result = credentialOfferService.createCredentialOfferUriResponse(nonce);
        StepVerifier.create(result)
                .expectNext("openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fexample.com%2Foid4vci%2Fv1%2Fcredential-offer%2Fabc123")
                .verifyComplete();
    }

}