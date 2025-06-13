package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.application.workflow.PreAuthorizedCodeWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialIssuanceRecord;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuanceRecordService;
import es.in2.issuer.backend.shared.domain.util.Utils;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.shared.objectmother.PreAuthorizedCodeResponseMother;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ActivationCodeWorkflowImplTest {

    @Mock
    private CredentialOfferService credentialOfferService;

    @Mock
    private CacheStore cacheStore;

    @Mock
    private PreAuthorizedCodeWorkflow preAuthorizedCodeWorkflow;

    @Mock
    private CredentialIssuanceRecordService credentialIssuanceRecordService;

    @InjectMocks
    private ActivationCodeWorkflowImpl credentialOfferIssuanceService;

    @Test
    void testBuildCredentialOfferUri() {
        String processId = "1234";
        String transactionCode = "4321";
        String credentialType = "VerifiableCredential";
        String credentialOfferUri = "https://example.com/1234";
        String txCode = "1234";
        PreAuthorizedCodeResponse preAuthorizedCodeResponse =
                PreAuthorizedCodeResponseMother.withPreAuthorizedCodeAndPin("4567", txCode);
        String cTransactionCode = "cTransactionCode";
        int expiry = 1000;
        CredentialIssuanceRecord credentialIssuanceRecord = new CredentialIssuanceRecord();
        credentialIssuanceRecord.setId(UUID.fromString("f712e67c-6a89-4696-b100-aba382336095"));
        credentialIssuanceRecord.setCredentialType(credentialType);

        try (MockedStatic<Utils> mockUtils = mockStatic(Utils.class)) {
            mockUtils.when(Utils::generateCustomNonce)
                    .thenReturn(Mono.just(transactionCode))
                    .thenReturn(Mono.just(cTransactionCode));

            when(cacheStore.get(transactionCode))
                    .thenReturn(Mono.just(credentialIssuanceRecord.getId().toString()));
            when(cacheStore.delete(transactionCode))
                    .thenReturn(Mono.empty());
            when(credentialIssuanceRecordService.get(credentialIssuanceRecord.getId().toString()))
                    .thenReturn(Mono.just(credentialIssuanceRecord));
            when(preAuthorizedCodeWorkflow.generatePreAuthorizedCode())
                    .thenReturn(Mono.just(preAuthorizedCodeResponse));
            when(credentialOfferService.buildCustomCredentialOffer(
                    credentialType,
                    preAuthorizedCodeResponse.preAuthorizedCode()))
                    .thenReturn(Mono.just(CredentialOffer.builder().build()));
            when(cacheStore.add(anyString(), any()))
                    .thenReturn(Mono.empty());
            when(cacheStore.getCacheExpiryInSeconds())
                    .thenReturn(Mono.just(expiry));
            when(credentialOfferService.createCredentialOfferUriResponse(anyString()))
                    .thenReturn(Mono.just(credentialOfferUri));
            CredentialOfferUriResponse expectedResponse = CredentialOfferUriResponse.builder()
                    .credentialOfferUri(credentialOfferUri)
                    .cActivationCode(cTransactionCode)
                    .cActivationCodeExpiresIn(expiry)
                    .build();
            StepVerifier.create(credentialOfferIssuanceService.buildCredentialOfferUri(processId, transactionCode))
                    .expectNext(expectedResponse)
                    .verifyComplete();
        }
    }

    @Test
    void testBuildNewCredentialOfferUri() {
        String processId = "1234";
        String transactionCode = "4321";
        String credentialType = "VerifiableCredential";
        String credentialOfferUri = "https://example.com/1234";
        String txCode = "1234";
        PreAuthorizedCodeResponse preAuthorizedCodeResponse =
                PreAuthorizedCodeResponseMother.withPreAuthorizedCodeAndPin("4567", txCode);
        String oldCTransactionCode = "oldCTransactionCode";
        String cTransactionCode = "cTransactionCode";
        int expiry = 1000;
        CredentialIssuanceRecord credentialIssuanceRecord = new CredentialIssuanceRecord();
        credentialIssuanceRecord.setId(UUID.fromString("f712e67c-6a89-4696-b100-aba382336095"));
        credentialIssuanceRecord.setCredentialType(credentialType);

        try (MockedStatic<Utils> mockUtils = mockStatic(Utils.class)) {
            mockUtils.when(Utils::generateCustomNonce)
                    .thenReturn(Mono.just(transactionCode))
                    .thenReturn(Mono.just(cTransactionCode));

            when(cacheStore.get(oldCTransactionCode))
                    .thenReturn(Mono.just(credentialIssuanceRecord.getId().toString()));
            when(cacheStore.delete(oldCTransactionCode))
                    .thenReturn(Mono.empty());
            when(credentialIssuanceRecordService.get(credentialIssuanceRecord.getId().toString()))
                    .thenReturn(Mono.just(credentialIssuanceRecord));
            when(preAuthorizedCodeWorkflow.generatePreAuthorizedCode())
                    .thenReturn(Mono.just(preAuthorizedCodeResponse));
            when(credentialOfferService.buildCustomCredentialOffer(
                    credentialType,
                    preAuthorizedCodeResponse.preAuthorizedCode()))
                    .thenReturn(Mono.just(CredentialOffer.builder().build()));
            when(cacheStore.add(anyString(), any()))
                    .thenReturn(Mono.empty());
            when(cacheStore.getCacheExpiryInSeconds())
                    .thenReturn(Mono.just(expiry));
            when(credentialOfferService.createCredentialOfferUriResponse(anyString()))
                    .thenReturn(Mono.just(credentialOfferUri));
            CredentialOfferUriResponse expectedResponse = CredentialOfferUriResponse.builder()
                    .credentialOfferUri(credentialOfferUri)
                    .cActivationCode(cTransactionCode)
                    .cActivationCodeExpiresIn(expiry)
                    .build();
            StepVerifier.create(credentialOfferIssuanceService.buildNewCredentialOfferUri(processId, oldCTransactionCode))
                    .expectNext(expectedResponse)
                    .verifyComplete();
        }
    }

}
