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
    private final CredentialProcedureService ;
    private final DeferredCredentialMetadataService;
    private final PreAuthorizedCodeWorkflow preAuthorizedCodeWorkflow;

    @Override
    public Mono<CredentialOfferUriResponse> buildCredentialOfferUri(String processId, String transactionCode) {
        // TODO: mirar a la caché -> i retornar el cirId
        return deferredCredentialMetadataService.validateTransactionCode(transactionCode)
                .then(Mono.just(transactionCode))
                .flatMap(this::buildCredentialOfferUriInternal);
    }

    @Override
    public Mono<CredentialOfferUriResponse> buildNewCredentialOfferUri(String processId, String cTransactionCode) {
        // TODO: actualitzar el key de l'issuanceMetada amb un nou nonce
        return deferredCredentialMetadataService.validateCTransactionCode(cTransactionCode)
                .flatMap(this::buildCredentialOfferUriInternal);
    }

    // Add logs to debug the process
    // TODO: es passa el cirId
    private Mono<CredentialOfferUriResponse> buildCredentialOfferUriInternal(String transactionCode) {
        //TODO: S'obté de fora
        return deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode)
                .flatMap(procedureId ->
                        // TODO: cir repostory findById
                        credentialProcedureService.getCredentialProcedureById(procedureId)
                                .flatMap(credentialProcedure ->
                                        // TODO treure el passar id, no ho necessita
                                        preAuthorizedCodeWorkflow.generatePreAuthorizedCode(Mono.just(credentialProcedure.getCredentialId()))
                                                .flatMap(preAuthorizedCodeResponse ->
                                                        // key-> nonce
                                                        // TODO: crear en nova caché issuanceMetadata -> caché guardes objecte issuanceMetadata ->
                                                        // la caché de l'issuance metadata no ha de ser un cop consultat ni als 10 minuts
                                                        //  String preAuthorizedCode
                                                        //  String credentialId,
                                                        // String txCode
                                                        // String email -> from DDBB cir
                                                                .flatMap(email ->
                                                                        credentialOfferService.buildCustomCredentialOffer(
                                                                                        credentialProcedure.getCredentialType(), // from ddbb cir
                                                                                        preAuthorizedCodeResponse.grants(), // TODO: es contruirà dins (només es passa el preAuthorizedCode)
                                                                                        email, // TODO: treure
                                                                                        preAuthorizedCodeResponse.pin() //TODO: treure
                                                                                )
                                                                                // TODO: afegir credentialOffer dins del issuanceMetadata
                                                                                //  en nova caché issuanceMetadata -> caché guardes objecte issuanceMetadata ->
                                                                                // Crear nonce del per l'Issuance Metadata
                                                                                // Guardo l'issuanceMetadata
                                                                                .flatMap(credentialOfferService::createCredentialOfferUriResponse)
                                                                )
                                                )
                                                .flatMap(credentialOfferUri ->
                                                        // TODO en una nova caché: cacheStoreForTransactionCode -> key: c_activation_code [generar nonce], value: nonce del issuanceMetadata
                                                        deferredCredentialMetadataService.updateCacheStoreForCTransactionCode(transactionCode)
                                                                .map(cTransactionCodeMap ->
                                                                        CredentialOfferUriResponse.builder()
                                                                                .credentialOfferUri(credentialOfferUri)
                                                                                // TODO: l'he generat abans com a nonce
                                                                                .cTransactionCode(cTransactionCodeMap.get("cTransactionCode").toString())
                                                                                // TODO: agafar la constant
                                                                                .cTransactionCodeExpiresIn(Integer.parseInt(cTransactionCodeMap.get("cTransactionCodeExpiresIn").toString()))
                                                                                .build()
                                                                )
                                                )
                                )
                );
    }

}
