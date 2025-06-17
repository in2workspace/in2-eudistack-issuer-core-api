package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.model.dto.Grants;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

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
        String processId = "b731b463-7473-4f97-be7a-658ec0b5dbc9";
        String credentialOfferId = "e0e2c6ab-8fe7-4709-82f0-4a771aaee841";
        String credentialOwnerEmail = "employee1@example.com";
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
                .credentialOwnerEmail(credentialOwnerEmail)
                .pin(txCode)
                .build();
        // Mocking the behavior of the dependencies
        when(credentialOfferCacheRepository.findCredentialOfferById(credentialOfferId))
                .thenReturn(Mono.just(credentialOfferData));
        when(emailService.sendTxCodeNotification(credentialOwnerEmail, "Pin Code", txCode))
                .thenReturn(Mono.empty());
        when(credentialOfferCacheRepository.findCredentialOfferById(credentialOfferId))
                .thenReturn(Mono.just(credentialOfferData));
        when(emailService.sendTxCodeNotification(credentialOfferData.credentialOwnerEmail(), "Pin Code", credentialOfferData.pin()))
                .thenReturn(Mono.empty());
        // Act
        Mono<CredentialOffer> result = credentialOfferWorkflow.getCredentialOfferById(processId, credentialOfferId);
        // Assert
        assertEquals(credentialOffer, result.block());
    }

}