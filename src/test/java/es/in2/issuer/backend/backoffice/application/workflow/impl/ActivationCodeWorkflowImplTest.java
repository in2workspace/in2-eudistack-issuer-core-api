package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.domain.service.impl.CredentialOfferServiceImpl;
import es.in2.issuer.backend.oidc4vci.application.workflow.PreAuthorizedCodeWorkflow;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ActivationCodeWorkflowImplTest {

    @Mock
    private CredentialOfferServiceImpl credentialOfferService;

    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @Mock
    private PreAuthorizedCodeWorkflow preAuthorizedCodeWorkflow;

    @InjectMocks
    private ActivationCodeWorkflowImpl credentialOfferIssuanceService;

    //todo
//    @Test
//    void testBuildCredentialOfferUri() {
//        String processId = "1234";
//        String transactionCode = "4321";
//        String procedureId = "uuid1234";
//        String credentialType = "VerifiableCredential";
//        String nonce = "nonce";
//        String credentialOfferUri = "https://example.com/1234";
//        String mail = "user@gmail.com";
//        String txCode = "1234";
//        PreAuthorizedCodeResponse preAuthorizedCodeResponse =
//                PreAuthorizedCodeResponseMother.withPreAuthorizedCodeAndPin("4567", txCode);
//        CredentialOfferData credentialOfferData = CredentialOfferData.builder()
//                .credentialOffer(CredentialOffer.builder().build())
//                .pin(txCode)
//                .employeeEmail(mail)
//                .build();
//        CredentialProcedure credentialProcedure = CredentialProcedure.builder()
//                .credentialId(UUID.fromString("871a85f6-e1dc-4b05-89c9-90914b59c843"))
//                .credentialType(credentialType)
//                .build();
//        String cTransactionCode = "cTransactionCode";
//        int expiry = 1000;
//        Map<String, Object> cTransactionCodeMap = new HashMap<>();
//        cTransactionCodeMap.put("cTransactionCode", cTransactionCode);
//        cTransactionCodeMap.put("cTransactionCodeExpiresIn", expiry);
//        when(deferredCredentialMetadataService.validateTransactionCode(transactionCode))
//                .thenReturn(Mono.empty());
//        when(deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode))
//                .thenReturn(Mono.just(procedureId));
//        when(credentialProcedureService.getCredentialProcedureById(procedureId))
//                .thenReturn(Mono.just(credentialProcedure));
//        when(preAuthorizedCodeWorkflow.generatePreAuthorizedCode(any()))
//                .thenReturn(Mono.just(preAuthorizedCodeResponse));
//        when(deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(
//                transactionCode, preAuthorizedCodeResponse.grants().preAuthorizedCode()))
//                .thenReturn(Mono.empty());
//        when(credentialProcedureService.getMandateeEmailFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(mail));
//        when(credentialOfferService.buildCustomCredentialOffer(
//                credentialType,
//                preAuthorizedCodeResponse.grants(),
//                mail,
//                preAuthorizedCodeResponse.pin()))
//                .thenReturn(Mono.just(credentialOfferData));
//        when(credentialOfferCacheRepository.saveCustomCredentialOffer(credentialOfferData))
//                .thenReturn(Mono.just(nonce));
//        when(credentialOfferService.createCredentialOfferUriResponse(nonce))
//                .thenReturn(Mono.just(credentialOfferUri));
//        when(deferredCredentialMetadataService.updateCacheStoreForCTransactionCode(transactionCode))
//                .thenReturn(Mono.just(cTransactionCodeMap));
//        CredentialOfferUriResponse expectedResponse = CredentialOfferUriResponse.builder()
//                .credentialOfferUri(credentialOfferUri)
//                .cTransactionCode(cTransactionCode)
//                .cTransactionCodeExpiresIn(expiry)
//                .build();
//        StepVerifier.create(credentialOfferIssuanceService.buildCredentialOfferUri(processId, transactionCode))
//                .expectNext(expectedResponse)
//                .verifyComplete();
//    }

//    @Test
//    void testBuildNewCredentialOfferUri() {
//        String processId = "1234";
//        String subTransactionCode = "9876";
//        String originalTransactionCode = "4321";
//        String procedureId = "uuid1234";
//        String credentialType = "VerifiableCredential";
//        String nonce = "nonce";
//        String credentialOfferUri = "https://example.com/1234";
//        String mail = "user@gmail.com";
//        String txCode = "1234";
//        PreAuthorizedCodeResponse preAuthorizedCodeResponse =
//                PreAuthorizedCodeResponseMother.withPreAuthorizedCodeAndPin("4567", txCode);
//        CredentialOfferData credentialOfferData = CredentialOfferData.builder()
//                .credentialOffer(CredentialOffer.builder().build())
//                .pin(txCode)
//                .employeeEmail(mail)
//                .build();
//        CredentialProcedure credentialProcedure = CredentialProcedure.builder()
//                .credentialId(UUID.fromString("871a85f6-e1dc-4b05-89c9-90914b59c843"))
//                .credentialType(credentialType)
//                .build();
//        // Se simula el Map con los detalles de cTransactionCode
//        String cTransactionCode = "cTransactionCode";
//        int expiry = 1000;
//        Map<String, Object> cTransactionCodeMap = new HashMap<>();
//        cTransactionCodeMap.put("cTransactionCode", cTransactionCode);
//        cTransactionCodeMap.put("cTransactionCodeExpiresIn", expiry);
//        // Stubbing
//        when(deferredCredentialMetadataService.validateCTransactionCode(subTransactionCode))
//                .thenReturn(Mono.just(originalTransactionCode));
//        when(deferredCredentialMetadataService.getProcedureIdByTransactionCode(originalTransactionCode))
//                .thenReturn(Mono.just(procedureId));
//        when(credentialProcedureService.getCredentialProcedureById(procedureId))
//                .thenReturn(Mono.just(credentialProcedure));
//        when(preAuthorizedCodeWorkflow.generatePreAuthorizedCode(
//                any()))
//                .thenReturn(Mono.just(preAuthorizedCodeResponse));
//        when(deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(
//                originalTransactionCode, preAuthorizedCodeResponse.grants().preAuthorizedCode()))
//                .thenReturn(Mono.empty());
//        when(credentialProcedureService.getMandateeEmailFromDecodedCredentialByProcedureId(procedureId))
//                .thenReturn(Mono.just(mail));
//        when(credentialOfferService.buildCustomCredentialOffer(
//                credentialType,
//                preAuthorizedCodeResponse.grants(),
//                mail,
//                preAuthorizedCodeResponse.pin()))
//                .thenReturn(Mono.just(credentialOfferData));
//        when(credentialOfferCacheRepository.saveCustomCredentialOffer(credentialOfferData))
//                .thenReturn(Mono.just(nonce));
//        when(credentialOfferService.createCredentialOfferUriResponse(nonce))
//                .thenReturn(Mono.just(credentialOfferUri));
//        when(deferredCredentialMetadataService.updateCacheStoreForCTransactionCode(originalTransactionCode))
//                .thenReturn(Mono.just(cTransactionCodeMap));
//        CredentialOfferUriResponse expectedResponse = CredentialOfferUriResponse.builder()
//                .credentialOfferUri(credentialOfferUri)
//                .cTransactionCode(cTransactionCode)
//                .cTransactionCodeExpiresIn(expiry)
//                .build();
//        StepVerifier.create(credentialOfferIssuanceService.buildNewCredentialOfferUri(processId, subTransactionCode))
//                .expectNext(expectedResponse)
//                .verifyComplete();
//    }

}
