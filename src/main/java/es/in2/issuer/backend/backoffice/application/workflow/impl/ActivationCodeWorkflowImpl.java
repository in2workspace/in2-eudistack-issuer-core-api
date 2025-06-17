package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.application.workflow.PreAuthorizedCodeWorkflow;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class ActivationCodeWorkflowImpl implements ActivationCodeWorkflow {

    private final CredentialOfferService credentialOfferService;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final PreAuthorizedCodeWorkflow preAuthorizedCodeWorkflow;

    @Override
    public Mono<CredentialOfferUriResponse> buildCredentialOfferUri(String processId, String transactionCode) {
        return deferredCredentialMetadataService.validateTransactionCode(transactionCode)
                .then(Mono.just(transactionCode))
                .flatMap(this::buildCredentialOfferUriInternal);
    }

    @Override
    public Mono<CredentialOfferUriResponse> buildNewCredentialOfferUri(String processId, String cTransactionCode) {
        return deferredCredentialMetadataService.validateCTransactionCode(cTransactionCode)
                .flatMap(this::buildCredentialOfferUriInternal);
    }

    // Add logs to debug the process
    private Mono<CredentialOfferUriResponse> buildCredentialOfferUriInternal(String transactionCode) {
        return deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode)
                .flatMap(procedureId ->
                        credentialProcedureService.getCredentialProcedureById(procedureId)
                                .flatMap(credentialProcedure ->
                                        preAuthorizedCodeWorkflow.generatePreAuthorizedCode(Mono.just(credentialProcedure.getCredentialId()))
                                                .flatMap(preAuthorizedCodeResponse ->
                                                        deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(
                                                                        transactionCode,
                                                                        preAuthorizedCodeResponse.grants().preAuthorizedCode()
                                                                )
                                                                .then(Mono.defer(() -> credentialOfferService.buildCustomCredentialOffer(
                                                                                credentialProcedure.getCredentialType(),
                                                                                preAuthorizedCodeResponse.grants(),
                                                                                credentialProcedure.getOwnerEmail(),
                                                                                preAuthorizedCodeResponse.pin()
                                                                        )
                                                                        .flatMap(credentialOfferCacheRepository::saveCustomCredentialOffer)
                                                                        .flatMap(credentialOfferService::createCredentialOfferUriResponse)))
                                                )
                                                .flatMap(credentialOfferUri ->
                                                        deferredCredentialMetadataService.updateCacheStoreForCTransactionCode(transactionCode)
                                                                .map(cTransactionCodeMap ->
                                                                        CredentialOfferUriResponse.builder()
                                                                                .credentialOfferUri(credentialOfferUri)
                                                                                .cTransactionCode(cTransactionCodeMap.get("cTransactionCode").toString())
                                                                                .cTransactionCodeExpiresIn(Integer.parseInt(cTransactionCodeMap.get("cTransactionCodeExpiresIn").toString()))
                                                                                .build()
                                                                )
                                                )
                                )
                );
    }

}
