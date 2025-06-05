package es.in2.issuer.backend.backoffice.application.workflow.impl;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.application.workflow.PreAuthorizedCodeWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuanceRecordService;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class ActivationCodeWorkflowImpl implements ActivationCodeWorkflow {

    private final CredentialOfferService credentialOfferService;
    private final CacheStore<String> cacheStoreForActivationCode;
    private final CacheStore<String> cacheStoreForCActivationCode;
    private final PreAuthorizedCodeWorkflow preAuthorizedCodeWorkflow;
    private final CredentialIssuanceRecordService credentialIssuanceRecordService;
    private final CacheStore<IssuanceMetadata> cacheStoreForIssuanceMetadata;

    @Override
    public Mono<CredentialOfferUriResponse> buildCredentialOfferUri(String processId, String activationCode) {
        log.debug("Validating ActivationCode: {}", activationCode);
        return validateActivationCode(activationCode)
                .flatMap(this::buildCredentialOfferUriInternal);
    }

    @Override
    public Mono<CredentialOfferUriResponse> buildNewCredentialOfferUri(String processId, String cActivationCode) {
        return validateCActivationCode(cActivationCode)
                .flatMap(this::buildCredentialOfferUriInternal);
    }

    private Mono<String> validateActivationCode(String activationCode) {
        return cacheStoreForActivationCode.get(activationCode)
                .flatMap(credentialIssuanceRecordId -> cacheStoreForActivationCode.delete(activationCode)
                        .thenReturn(credentialIssuanceRecordId));
    }

    private Mono<String> validateCActivationCode(String cActivationCode) {
        log.debug("Validating cActivationCode: {}", cActivationCode);
        return cacheStoreForCActivationCode.get(cActivationCode)
                .flatMap(activationCode -> cacheStoreForCActivationCode.delete(cActivationCode)
                        .thenReturn(activationCode));
    }

    private Mono<CredentialOfferUriResponse> buildCredentialOfferUriInternal(String credentialIssuanceRecordId) {
        return credentialIssuanceRecordService.get(credentialIssuanceRecordId)
                .flatMap(credentialIssuanceRecord ->
                        preAuthorizedCodeWorkflow.generatePreAuthorizedCode()
                                // todo guardar preauthorizedcode al cir
                                .flatMap(preAuthorizedCodeResponse ->
                                        credentialOfferService.buildCustomCredentialOffer(
                                                        credentialIssuanceRecord.getCredentialType(),
                                                        preAuthorizedCodeResponse.preAuthorizedCode())
                                                .flatMap(credentialOffer ->
                                                        buildIssuanceMetadata(
                                                                preAuthorizedCodeResponse.preAuthorizedCode(),
                                                                credentialIssuanceRecord.getId().toString(),
                                                                preAuthorizedCodeResponse.txCode(),
                                                                credentialIssuanceRecord.getEmail(),
                                                                credentialOffer)
                                                                .flatMap(issuanceMetadata ->
                                                                        generateCustomNonce()
                                                                                .flatMap(activationCodeNonce ->
                                                                                        cacheStoreForIssuanceMetadata.add(activationCodeNonce, issuanceMetadata)
                                                                                                .then(credentialOfferService.createCredentialOfferUriResponse(activationCodeNonce))
                                                                                                .flatMap(credentialOfferUri ->
                                                                                                        generateCustomNonce()
                                                                                                                .flatMap(cActivationCodeNonce ->
                                                                                                                        cacheStoreForCActivationCode.add(cActivationCodeNonce, activationCodeNonce)
                                                                                                                                .then(buildCredentialOfferUriResponse(credentialOfferUri, cActivationCodeNonce))
                                                                                                                )
                                                                                                )
                                                                                )
                                                                )
                                                )
                                )
                );
    }

    private Mono<IssuanceMetadata> buildIssuanceMetadata(String preAuthorizedCode, String credentialIssuanceRecordId,
                                                         String txCode, String email, CredentialOffer credentialOffer) {
        return Mono.just(IssuanceMetadata.builder()
                .preAuthorizedCode(preAuthorizedCode)
                .credentialIssuanceRecordId(credentialIssuanceRecordId)
                .txCode(txCode)
                .email(email)
                .credentialOffer(credentialOffer)
                .build());
    }

    private Mono<CredentialOfferUriResponse> buildCredentialOfferUriResponse(String credentialOfferUri, String activationCodeNonce) {
        return cacheStoreForCActivationCode.getCacheExpiryInSeconds()
                .flatMap(cActivationCodeExpiresIn ->
                        Mono.just(CredentialOfferUriResponse.builder()
                                .credentialOfferUri(credentialOfferUri)
                                .cActivationCode(activationCodeNonce)
                                .cActivationCodeExpiresIn(cActivationCodeExpiresIn)
                                .build()));
    }
}
