package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.VerifiableCredentialService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.VerifiableCertificationFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.VERIFIABLE_CERTIFICATION;


@Service
@RequiredArgsConstructor
@Slf4j
public class VerifiableCredentialServiceImpl implements VerifiableCredentialService {
    private final CredentialFactory credentialFactory;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    private final VerifiableCertificationFactory verifiableCertificationFactory;
    private final IssuerFactory issuerFactory;

    @Override
    public Mono<String> generateVc(String processId, String vcType, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String token) {
        return credentialFactory.mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialDataRequest, token)
                .flatMap(credentialProcedureService::createCredentialProcedure)
                //TODO repensar esto cuando el flujo del Verification cumpla con el OIDC4VC
                //Generate Issuer and Signer using LEARCredentialEmployee method
                .flatMap(procedureId -> deferredCredentialMetadataService.createDeferredCredentialMetadata(
                                procedureId,
                                preSubmittedCredentialDataRequest.operationMode(),
                                preSubmittedCredentialDataRequest.responseUri())
                        .flatMap(transactionCode ->
                                credentialProcedureService.updateFormatByProcedureId(procedureId, preSubmittedCredentialDataRequest.format())
                                        .then(deferredCredentialMetadataService.updateFormatByProcedureId(procedureId, preSubmittedCredentialDataRequest.format()))
                                        .thenReturn(transactionCode)));
    }

    @Override
    public Mono<String> generateVerifiableCertification(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String idToken) {
        return credentialFactory.mapCredentialIntoACredentialProcedureRequest(processId, preSubmittedCredentialDataRequest, idToken)
                .flatMap(credentialProcedureService::createCredentialProcedure)
                .flatMap(procedureId ->
                        deferredCredentialMetadataService.createDeferredCredentialMetadata(
                                        procedureId,
                                        preSubmittedCredentialDataRequest.operationMode(),
                                        preSubmittedCredentialDataRequest.responseUri()
                                )
                                .thenReturn(procedureId)
                )
                .flatMap(procedureId ->
                        issuerFactory.createIssuer(procedureId, VERIFIABLE_CERTIFICATION)
                                .flatMap(issuer -> verifiableCertificationFactory.mapIssuerAndSigner(procedureId, issuer))
                                .flatMap(bindVerifiableCertification ->
                                        credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindVerifiableCertification, JWT_VC)
                                )
                                .onErrorResume(error -> {
                                    log.error("Error generating issuer/signer, continuing in ASYNC mode", error);
                                    return Mono.empty();
                                })
                                .thenReturn(procedureId)
                );
    }


    @Override
    public Mono<DeferredCredentialResponse> generateDeferredCredentialResponse(String processId, DeferredCredentialRequest deferredCredentialRequest) {
        return deferredCredentialMetadataService.getVcByTransactionId(deferredCredentialRequest.transactionId())
                .flatMap(deferredCredentialMetadataDeferredResponse -> {
                    if (deferredCredentialMetadataDeferredResponse.vc() != null) {
                        return credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(deferredCredentialMetadataDeferredResponse.procedureId())
                                .then(deferredCredentialMetadataService.deleteDeferredCredentialMetadataById(deferredCredentialMetadataDeferredResponse.id()))
                                .then(Mono.just(DeferredCredentialResponse.builder()
                                        .credentials(List.of(deferredCredentialMetadataDeferredResponse.vc()))
                                        .build()));
                    } else {
                        return Mono.just(DeferredCredentialResponse.builder()
                                .build());
                    }
                });
    }

    @Override
    public Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, String accessToken, String preAuthCode) {
        try {
            JWSObject jwsObject = JWSObject.parse(accessToken);
            String newAuthServerNonce = jwsObject.getPayload().toJSONObject().get("jti").toString();
            return deferredCredentialMetadataService.updateAuthServerNonceByAuthServerNonce(newAuthServerNonce, preAuthCode);
        } catch (ParseException e) {
            throw new RuntimeException();
        }

    }

    @Override
    public Mono<CredentialResponse> buildCredentialResponse(String processId, String subjectDid, String authServerNonce, String token) {
        return deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(authServerNonce)
                .flatMap(procedureId -> {
                    log.info("Procedure ID obtained: {}", procedureId);
                    return credentialProcedureService.getCredentialTypeByProcedureId(procedureId)
                            .flatMap(credentialType -> {
                                log.info("Credential Type obtained: {}", credentialType);
                                return credentialProcedureService.getDecodedCredentialByProcedureId(procedureId)
                                        .flatMap(decodedCredential -> {
                                            log.info("Decoded Credential obtained: {}", decodedCredential);
                                            return credentialFactory.mapCredentialAndBindMandateeId(processId, credentialType, decodedCredential, subjectDid)
                                                    .flatMap(bindCredentialWithMandateeId ->
                                                            credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindCredentialWithMandateeId)
                                                            .then(deferredCredentialMetadataService.updateDeferredCredentialMetadataByAuthServerNonce(authServerNonce))
                                                            .flatMap(transactionId -> {
                                                                log.info("Transaction ID obtained: {}", transactionId);
                                                                return deferredCredentialMetadataService.getFormatByProcedureId(procedureId)
                                                                        .flatMap(format ->
                                                                                credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, bindCredentialWithMandateeId, credentialType, format, authServerNonce)
                                                                                .then(credentialProcedureService.getOperationModeByProcedureId(procedureId))
                                                                                .flatMap(actualOperationMode -> buildCredentialResponseBasedOnOperationMode(actualOperationMode, procedureId, transactionId, authServerNonce, token)));
                                                            }));
                                        });
                            });
                });
    }


    private Mono<CredentialResponse> buildCredentialResponseBasedOnOperationMode(String operationMode, String procedureId, String transactionId, String authServerNonce, String token) {
        if (operationMode.equals(ASYNC)) {
            return credentialProcedureService.getDecodedCredentialByProcedureId(procedureId)
                    .flatMap(decodedCredential -> {
                        log.debug("ASYNC Credential JSON: {}", decodedCredential);
                        return Mono.just(CredentialResponse.builder()
                                .credentials(List.of(
                                        CredentialResponse.Credential.builder()
                                                .credential(decodedCredential)
                                                .build()))
                                .transactionId(transactionId)
                                .build());
                    });
        } else if (operationMode.equals(SYNC)) {
            return deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(authServerNonce)
                    .flatMap(procedureIdReceived ->
                            credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(BEARER_PREFIX + token, procedureIdReceived, JWT_VC)
                                    .flatMap(signedCredential -> Mono.just(CredentialResponse.builder()
                                            .credentials(List.of(
                                                    CredentialResponse.Credential.builder()
                                                            .credential(signedCredential)
                                                            .build()))
                                            .build()))
                                    .onErrorResume(error -> {
                                        if (error instanceof RemoteSignatureException || error instanceof IllegalArgumentException) {
                                            log.info("Error in SYNC mode, retrying with new operation mode");
                                            return credentialProcedureService.getDecodedCredentialByProcedureId(procedureIdReceived)
                                                    .flatMap(unsignedCredential ->
                                                            Mono.just(CredentialResponse.builder()
                                                                    .credentials(List.of(
                                                                            CredentialResponse.Credential.builder()
                                                                                    .credential(unsignedCredential)
                                                                                    .build()))
                                                                    .transactionId(transactionId)
                                                                    .build()));
                                        }
                                        return Mono.error(error);
                                    })
                    );
        } else {
            return Mono.error(new IllegalArgumentException("Unknown operation mode: " + operationMode));
        }
    }

}
