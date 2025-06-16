package es.in2.issuer.backend.shared.application.workflow.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialIssuanceRecord;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatus;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.VERIFIABLE_CERTIFICATION;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialIssuanceWorkflowImpl implements CredentialIssuanceWorkflow {

    private final AccessTokenService accessTokenService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final AppConfig appConfig;
    private final ProofValidationService proofValidationService;
    private final EmailService emailService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final VerifiableCredentialPolicyAuthorizationService verifiableCredentialPolicyAuthorizationService;
    private final TrustFrameworkService trustFrameworkService;
    private final LEARCredentialEmployeeFactory credentialEmployeeFactory;
    private final IssuerApiClientTokenService issuerApiClientTokenService;
    private final M2MTokenService m2mTokenService;
    private final CredentialDeliveryService credentialDeliveryService;
    private final CredentialIssuanceRecordService credentialIssuanceRecordService;
    private final CredentialFactory credentialFactory;
    private final IssuerFactory issuerFactory;

    @Override
    public Mono<Void> execute(String processId, PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest, String bearerToken, String idToken) {
        return accessTokenService.getCleanBearerToken(bearerToken).flatMap(
                token ->
                        // TODO: In the future the policy authorization will be done by an authorized filter
                        verifiableCredentialPolicyAuthorizationService.authorize(token, preSubmittedDataCredentialRequest.schema(), preSubmittedDataCredentialRequest.payload(), idToken)
                                .then(Mono.defer(() -> {
                                    if (preSubmittedDataCredentialRequest.schema().equals(VERIFIABLE_CERTIFICATION)) {
                                        return issuanceFromServiceWithDelegatedAuthorization(processId, preSubmittedDataCredentialRequest, idToken);
                                    } else if (preSubmittedDataCredentialRequest.schema().equals(LEAR_CREDENTIAL_EMPLOYEE)) {
                                        return issuanceFromService(processId, preSubmittedDataCredentialRequest, token);
                                    }

                                    return Mono.error(new CredentialTypeUnsupportedException(preSubmittedDataCredentialRequest.schema()));
                                })));
    }

    private @NotNull Mono<Void> issuanceFromServiceWithDelegatedAuthorization(String processId, PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest, String idToken) {
        return ensurePreSubmittedCredentialResponseUriIsNotNullOrBlank(preSubmittedDataCredentialRequest)
                .then(ensureVerifiableCertificationHasIdToken(preSubmittedDataCredentialRequest, idToken)
                        .then(verifiableCredentialService.generateVerifiableCertification(processId, preSubmittedDataCredentialRequest, idToken)
                                .flatMap(procedureId -> issuerApiClientTokenService.getClientToken()
                                        .flatMap(internalToken -> credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(
                                                BEARER_PREFIX + internalToken,
                                                procedureId,
                                                JWT_VC))
                                        // TODO instead of updating the credential status to valid,
                                        //  we should update the credential status to pending download
                                        //  but we don't support the verifiable certification download yet
                                        .flatMap(encodedVc -> {
                                            // Extract values from payload
                                            String productId = preSubmittedDataCredentialRequest.payload()
                                                    .get(CREDENTIAL_SUBJECT)
                                                    .get(PRODUCT)
                                                    .get(PRODUCT_ID)
                                                    .asText();

                                            String companyEmail = preSubmittedDataCredentialRequest.payload()
                                                    .get(CREDENTIAL_SUBJECT)
                                                    .get(COMPANY)
                                                    .get(EMAIL)
                                                    .asText();
                                            return credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId)
                                                    .then(m2mTokenService.getM2MToken()
                                                            .flatMap(m2mAccessToken ->
                                                                    credentialDeliveryService.sendVcToResponseUri(
                                                                            preSubmittedDataCredentialRequest.responseUri(),
                                                                            encodedVc,
                                                                            productId,
                                                                            companyEmail,
                                                                            m2mAccessToken.accessToken())));
                                        }))));
    }

    private Mono<Void> ensurePreSubmittedCredentialResponseUriIsNotNullOrBlank(PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest) {
        if (preSubmittedDataCredentialRequest.responseUri() == null || preSubmittedDataCredentialRequest.responseUri().isBlank()) {
            return Mono.error(new OperationNotSupportedException("For schema: " + preSubmittedDataCredentialRequest.schema() + " response_uri is required"));
        }
        return Mono.empty();
    }

    private Mono<Void> ensureVerifiableCertificationHasIdToken(PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest, String idToken) {
        if (preSubmittedDataCredentialRequest.schema().equals(VERIFIABLE_CERTIFICATION) && idToken == null) {
            return Mono.error(new MissingIdTokenHeaderException("Missing required ID Token header for VerifiableCertification issuance."));
        }
        return Mono.empty();
    }

    private @NotNull Mono<Void> issuanceFromService(String processId, PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest, String token) {
        return credentialIssuanceRecordService.create(processId, preSubmittedDataCredentialRequest, token)
                .flatMap(activationCode -> sendActivationCredentialEmail(activationCode, preSubmittedDataCredentialRequest));
    }

    private Mono<Void> sendActivationCredentialEmail(String activationCode, PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest) {
        String email = preSubmittedDataCredentialRequest.payload().get(MANDATEE).get(EMAIL).asText();
        String user = preSubmittedDataCredentialRequest.payload().get(MANDATEE).get(FIRST_NAME).asText() + " " + preSubmittedDataCredentialRequest.payload().get(MANDATEE).get(LAST_NAME).asText();
        String organization = preSubmittedDataCredentialRequest.payload().get(MANDATOR).get(ORGANIZATION).asText();

        String credentialOfferUrl = UriComponentsBuilder
                .fromHttpUrl(appConfig.getIssuerFrontendUrl())
                .path("/credentials/activation/" + activationCode)
                .build()
                .toUriString();

        return emailService.sendCredentialActivationEmail(email, CREDENTIAL_ACTIVATION_EMAIL_SUBJECT, credentialOfferUrl, appConfig.getKnowledgebaseWalletUrl(), user, organization)
                .onErrorMap(exception ->
                        new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    @Override
    public Mono<VerifiableCredentialResponse> generateVerifiableCredentialResponse(String processId,
                                                                                   CredentialRequest credentialRequest,
                                                                                   String authorizationHeader) {
        return accessTokenService.getCleanBearerToken(authorizationHeader)
                .flatMap(token -> {
                    try {
                        JWSObject jwsObject = JWSObject.parse(token);

                        String accessTokenJti = jwsObject.getPayload().toJSONObject().get("jti").toString();

                        return credentialIssuanceRecordService.getByJti(accessTokenJti)
                                .flatMap(credentialIssuanceRecord -> {
                                    if (credentialRequest.proofs() != null && !credentialRequest.proofs().jwt().isEmpty()) {
                                        return proofValidationService.ensureIsProofValid(credentialRequest.proofs().jwt().get(0), token)
                                                .then(extractDidFromJwtProof(credentialRequest.proofs().jwt().get(0))
                                                        .flatMap(did -> credentialFactory.credentialSubjectBinder(
                                                                        credentialIssuanceRecord.getCredentialData(),
                                                                        credentialIssuanceRecord.getCredentialType(),
                                                                        did)
                                                                .flatMap(credentialWithDid ->
                                                                        buildVerifiableCredentialResponse(
                                                                                processId,
                                                                                token,
                                                                                credentialIssuanceRecord,
                                                                                credentialWithDid))));
                                    } else {
                                        return buildVerifiableCredentialResponse(
                                                processId,
                                                token,
                                                credentialIssuanceRecord,
                                                credentialIssuanceRecord.getCredentialData());
                                    }
                                });
                    } catch (ParseException e) {
                        log.error("Error parsing the accessToken", e);
                        throw new ParseErrorException("Error parsing accessToken");
                    }
                });
    }

    private @NotNull Mono<VerifiableCredentialResponse> buildVerifiableCredentialResponse(String processId, String token, CredentialIssuanceRecord credentialIssuanceRecord, String credentialWithDid) {
        return issuerFactory.createIssuer(credentialIssuanceRecord.getId().toString(), credentialIssuanceRecord.getCredentialType())
                .flatMap(detailedIssuer ->
                        credentialFactory.setIssuer(credentialWithDid, detailedIssuer)
                                .flatMap(credentialFactory::setCredentialStatus)
                                .flatMap(credentialWithStatus ->
                                        credentialSignerWorkflow.signAndUpdateCredential(
                                                        credentialIssuanceRecord.getId().toString(),
                                                        credentialIssuanceRecord.getCredentialFormat(),
                                                        credentialIssuanceRecord.getCredentialType(),
                                                        credentialWithStatus,
                                                        BEARER_PREFIX + token)
                                                .flatMap(signedCredential -> {
                                                    var response = VerifiableCredentialResponse.builder()
                                                            .credential(credentialWithStatus)
                                                            .transactionId(credentialIssuanceRecord.getTransactionId())
                                                            .build();
                                                    return credentialIssuanceRecordService
                                                            .getOperationModeById(
                                                                    credentialIssuanceRecord.getId().toString())
                                                            .flatMap(currentOperationMode ->
                                                                    handleOperationMode(
                                                                            currentOperationMode,
                                                                            processId,
                                                                            credentialIssuanceRecord.getAccessTokenJti(),
                                                                            response)
                                                                            .flatMap(handledResponse ->
                                                                                    credentialIssuanceRecordService.update(credentialIssuanceRecord)
                                                                                            .thenReturn(handledResponse)));
                                                })));
    }

    private Mono<VerifiableCredentialResponse> handleOperationMode(String operationMode, String processId, String authServerNonce, VerifiableCredentialResponse credentialResponse) {
        return switch (operationMode) {
            case ASYNC -> deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(authServerNonce)
                    .flatMap(procedureId ->
                            credentialProcedureService.getDecodedCredentialByProcedureId(procedureId)
                                    .flatMap(decodedCredential ->
                                            credentialProcedureService.getCredentialTypeByProcedureId(procedureId)
                                                    .flatMap(credentialType -> credentialProcedureService.getSignerEmailFromDecodedCredentialByProcedureId(decodedCredential, credentialType)
                                                            .flatMap(email -> emailService.sendPendingCredentialNotification(email, "Pending Credential")
                                                                    .thenReturn(credentialResponse)))));
            case SYNC -> deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(authServerNonce)
                    .flatMap(id -> credentialProcedureService.getCredentialStatusByProcedureId(id)
                            .flatMap(status -> {
                                Mono<Void> updateMono = !CredentialStatus.PEND_SIGNATURE.toString().equals(status)
                                        ? credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(id)
                                        : Mono.empty();
                                return updateMono.then(credentialProcedureService.getDecodedCredentialByProcedureId(id));
                            })
                            .flatMap(decodedCredential -> processDecodedCredential(processId, decodedCredential))
                    )
                    .thenReturn(credentialResponse);
            default -> Mono.error(new IllegalArgumentException("Unknown operation mode: " + operationMode));
        };
    }

    @Override
    public Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, AuthServerNonceRequest authServerNonceRequest) {
        return verifiableCredentialService.bindAccessTokenByPreAuthorizedCode
                (processId, authServerNonceRequest.accessToken(), authServerNonceRequest.preAuthorizedCode());
    }

    @Override
    public Mono<BatchCredentialResponse> generateVerifiableCredentialBatchResponse(
            String username,
            BatchCredentialRequest batchCredentialRequest,
            String token
    ) {
        return Flux.fromIterable(batchCredentialRequest.credentialRequests())
                .flatMap(credentialRequest -> generateVerifiableCredentialResponse(username, credentialRequest, token)
                        .map(verifiableCredentialResponse -> new BatchCredentialResponse.CredentialResponse(verifiableCredentialResponse.credential())))
                .collectList()
                .map(BatchCredentialResponse::new);
    }

    @Override
    public Mono<VerifiableCredentialResponse> generateVerifiableCredentialDeferredResponse(String processId, DeferredCredentialRequest deferredCredentialRequest) {
        return verifiableCredentialService.generateDeferredCredentialResponse(processId, deferredCredentialRequest)
                .onErrorResume(e -> Mono.error(new RuntimeException("Failed to process the credential for the next processId: " + processId, e)));
    }

    private Mono<String> extractDidFromJwtProof(String jwtProof) {
        return Mono.fromCallable(() -> {
            JWSObject jwsObject = JWSObject.parse(jwtProof);
            // Extract the issuer DID from the kid claim in the header
            String kid = jwsObject.getHeader().toJSONObject().get("kid").toString();
            // Split the kid string at '#' and take the first part
            return kid.split("#")[0];
        });
    }

    private Mono<Void> processDecodedCredential(String processId, String decodedCredential) {
        log.info("ProcessID: {} Decoded Credential: {}", processId, decodedCredential);

        LEARCredentialEmployee learCredentialEmployee = credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential);

        String mandatorOrgIdentifier = learCredentialEmployee.credentialSubject().mandate().mandator().organizationIdentifier();
        if (mandatorOrgIdentifier == null || mandatorOrgIdentifier.isBlank()) {
            log.error("ProcessID: {} Mandator Organization Identifier cannot be null or empty", processId);
            return Mono.error(new IllegalArgumentException("Organization Identifier not valid"));
        }

        return saveToTrustFramework(processId, mandatorOrgIdentifier);
    }

    private Mono<Void> saveToTrustFramework(String processId, String mandatorOrgIdentifier) {

        String mandatorDid = DID_ELSI + mandatorOrgIdentifier;

        return trustFrameworkService.validateDidFormat(processId, mandatorDid)
                .flatMap(isValid -> registerDidIfValid(processId, mandatorDid, isValid));
    }

    private Mono<Void> registerDidIfValid(String processId, String did, boolean isValid) {
        if (isValid) {
            return trustFrameworkService.registerDid(processId, did);
        } else {
            log.error("ProcessID: {} Did not registered because is invalid", processId);
            return Mono.empty();
        }
    }
}
