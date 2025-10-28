package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.model.dto.Grants;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialOfferWorkflowImplTest {

    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private CredentialOfferWorkflowImpl credentialOfferWorkflow;

    @Test
    void testGetCredentialOffer() {
        // Arrange
        // English comments as requested by the user
        String processId = "b731b463-7473-4f97-be7a-658ec0b5dbc9";
        String credentialOfferId = "e0e2c6ab-8fe7-4709-82f0-4a771aaee841";
        String credentialEmail = "employee1@example.com";
        String txCode = "1234";

        Grants grants = Grants.builder()
                .preAuthorizedCode("oaKazRN8I0IbtZ0C7JuMn5")
                .txCode(Grants.TxCode.builder()
                        .length(4)
                        .inputMode("numeric")
                        .description("Please provide the one-time code that was sent via e-mail")
                        .build())
                .build();

        CredentialOffer credentialOffer = CredentialOffer.builder()
                .credentialIssuer("https://credential-issuer.example.com")
                .credentialConfigurationIds(List.of("LEARCredentialEmployee"))
                .grants(Map.of("urn:ietf:params:oauth:grant-type:pre-authorized_code", grants))
                .build();

        CredentialOfferData credentialOfferData = CredentialOfferData.builder()
                .credentialOffer(credentialOffer)
                .credentialEmail(credentialEmail)
                .pin(txCode)
                .build();

        // Mock repository returns the offer data
        when(credentialOfferCacheRepository.findCredentialOfferById(credentialOfferId))
                .thenReturn(Mono.just(credentialOfferData));

        // IMPORTANT: match the template key used in the implementation ("email.pin-code")
        when(emailService.sendTxCodeNotification(credentialEmail, "email.pin-code", txCode))
                .thenReturn(Mono.empty());

        // Act
        Mono<CredentialOffer> result = credentialOfferWorkflow.getCredentialOfferById(processId, credentialOfferId);

        // Assert using StepVerifier (non-blocking)
        StepVerifier.create(result)
                .expectNext(credentialOffer) // same instance returned downstream
                .verifyComplete();

        // Verify interactions happen in the expected order
        InOrder inOrder = inOrder(credentialOfferCacheRepository, emailService);
        inOrder.verify(credentialOfferCacheRepository).findCredentialOfferById(credentialOfferId);
        inOrder.verify(emailService).sendTxCodeNotification(credentialEmail, "email.pin-code", txCode);
        inOrder.verifyNoMoreInteractions();
    }
}
