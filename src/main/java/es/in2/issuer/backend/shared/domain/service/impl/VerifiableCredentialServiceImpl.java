package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.VerifiableCredentialService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.statusList.application.StatusListWorkflow;
import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;


@Service
@RequiredArgsConstructor
@Slf4j
public class VerifiableCredentialServiceImpl implements VerifiableCredentialService {
    private final CredentialFactory credentialFactory;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final StatusListWorkflow statusListWorkflow;

    @Override
    public Mono<String> generateVc(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String email, String token) {
        String procedureId = UUID.randomUUID().toString();

        return statusListWorkflow
                .allocateEntry(StatusPurpose.REVOCATION, procedureId, token)
                .map(this::toCredentialStatus)
                .flatMap(credentialStatus ->
                        credentialFactory.mapCredentialIntoACredentialProcedureRequest(
                                processId,
                                procedureId,
                                preSubmittedCredentialDataRequest,
                                credentialStatus,
                                email
                        )
                )
                .flatMap(credentialProcedureService::createCredentialProcedure)
                .then(deferredCredentialMetadataService.createDeferredCredentialMetadata(
                        procedureId,
                        preSubmittedCredentialDataRequest.operationMode(),
                        preSubmittedCredentialDataRequest.responseUri())
                )
                .flatMap(transactionCode ->
                        credentialProcedureService.updateFormatByProcedureId(procedureId, preSubmittedCredentialDataRequest.format())
                                .then(deferredCredentialMetadataService.updateFormatByProcedureId(procedureId, preSubmittedCredentialDataRequest.format()))
                                .thenReturn(transactionCode)
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
    public Mono<CredentialResponse> buildCredentialResponse(
            String processId,
            String subjectDid,
            String authServerNonce,
            String token,
            String email,
            String procedureId) {
        return credentialProcedureService
                        .getCredentialTypeByProcedureId(procedureId)
                        .zipWhen(credType -> credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
                        .flatMap(tuple -> {
                            String credentialType = tuple.getT1();
                            String decoded = tuple.getT2();

                            return bindAndSaveIfNeeded(
                                    processId,
                                    procedureId,
                                    credentialType,
                                    decoded,
                                    subjectDid
                            )
                                    .flatMap(boundCred -> updateDeferredCredentialAndBuildResponse(
                                            processId,
                                            procedureId,
                                            authServerNonce,
                                            token,
                                            email
                                    ));
                        });
    }

    private Mono<String> bindAndSaveIfNeeded(
            String processId,
            String procedureId,
            String credentialType,
            String decodedCredential,
            String subjectDid) {
        if (subjectDid == null) {
            return Mono.just(decodedCredential);
        }

        return credentialFactory
                .bindCryptographicCredentialSubjectId(
                        processId,
                        credentialType,
                        decodedCredential,
                        subjectDid)
                .onErrorResume(e -> {
                    log.error("Error binding cryptographic credential subject ID: {}", e.getMessage(), e);
                    return Mono.error(new RuntimeException("Failed to bind cryptographic credential subject", e));
                })
                .flatMap(bound -> credentialProcedureService
                        .updateDecodedCredentialByProcedureId(procedureId, bound)
                        .thenReturn(bound)
                );
    }

    private Mono<CredentialResponse> updateDeferredCredentialAndBuildResponse(
            String processId,
            String procedureId,
            String authServerNonce,
            String token,
            String email) {
        log.debug(
                "Updating deferred credential [processId={}, procedureId={}, authServerNonce={}]",
                processId,
                procedureId,
                authServerNonce
        );

        return deferredCredentialMetadataService
                .updateDeferredCredentialMetadataByAuthServerNonce(authServerNonce)
                .onErrorResume(e -> {
                    log.error("Error updating deferred metadata with authServerNonce: {}", e.getMessage(), e);
                    return Mono.error(new RuntimeException("Failed to update deferred metadata", e));
                })
                .switchIfEmpty(Mono.error(new RuntimeException("TransactionId not found after updating deferred metadata")))
                .flatMap(transactionId ->
                        deferredCredentialMetadataService
                                .getFormatByProcedureId(procedureId)
                                .onErrorResume(e -> {
                                    log.error("Error mapping/binding issuer and updating credential: {}", e.getMessage(), e);
                                    return Mono.error(new RuntimeException("Failed to retrieve credential format", e));
                                })
                                .switchIfEmpty(Mono.error(new RuntimeException("Credential format not found for procedureId: " + procedureId)))
                                .flatMap(format ->
                                        credentialProcedureService
                                                .getOperationModeByProcedureId(procedureId)
                                                .switchIfEmpty(Mono.error(new RuntimeException("Operation mode not found for procedureId: " + procedureId)))
                                                .flatMap(mode ->
                                                        buildCredentialResponseBasedOnOperationMode(
                                                                processId,
                                                                mode,
                                                                procedureId,
                                                                transactionId,
                                                                token,
                                                                email
                                                        )
                                                )
                                )
                );
    }

    private Mono<CredentialResponse> buildCredentialResponseBasedOnOperationMode(
            String processId,
            String operationMode,
            String procedureId,
            String transactionId,
            String token,
            String email) {
        if (ASYNC.equals(operationMode)) {
            return credentialProcedureService
                    .getDecodedCredentialByProcedureId(procedureId)
                    .flatMap(decodedCredential -> Mono.just(
                            CredentialResponse.builder()
                                    .credentials(List.of(
                                            CredentialResponse.Credential.builder()
                                                    .credential(decodedCredential)
                                                    .build()
                                    ))
                                    .transactionId(transactionId)
                                    .build()
                    ));
        } else if (SYNC.equals(operationMode)) {
            return credentialSignerWorkflow
                            .signAndUpdateCredentialByProcedureId(
                                    processId,
                                    BEARER_PREFIX + token,
                                    procedureId,
                                    JWT_VC,
                                    email
                            )
                            .flatMap(signed -> Mono.just(
                                    CredentialResponse.builder()
                                            .credentials(List.of(
                                                    CredentialResponse.Credential.builder()
                                                            .credential(signed)
                                                            .build()
                                            ))
                                            .build()
                            ))
                            .onErrorResume(error -> {
                                if (error instanceof RemoteSignatureException
                                        || error instanceof IllegalArgumentException) {
                                    log.info("Error in SYNC mode, falling back to unsigned");
                                    return credentialProcedureService
                                            .getDecodedCredentialByProcedureId(procedureId)
                                            .flatMap(unsigned -> Mono.just(
                                                    CredentialResponse.builder()
                                                            .credentials(List.of(
                                                                    CredentialResponse.Credential.builder()
                                                                            .credential(unsigned)
                                                                            .build()
                                                            ))
                                                            .transactionId(transactionId)
                                                            .build()
                                            ));
                                }
                                return Mono.error(error);
                            });
        } else {
            return Mono.error(new IllegalArgumentException(
                    "Unknown operation mode: " + operationMode
            ));
        }
    }

    private CredentialStatus toCredentialStatus(StatusListEntry entry) {
        return CredentialStatus.builder()
                .id(entry.id())
                .type(entry.type())
                .statusPurpose(entry.statusPurpose().value())
                .statusListIndex(String.valueOf(entry.statusListIndex()))
                .statusListCredential(entry.statusListCredential())
                .build();
    }

}
