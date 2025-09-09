package es.in2.issuer.backend.shared.application.workflow.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.entities.DeferredCredentialMetadata;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_MACHINE;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialIssuanceWorkflowImpl implements CredentialIssuanceWorkflow {

    private final VerifiableCredentialService verifiableCredentialService;
    private final AppConfig appConfig;
    private final ProofValidationService proofValidationService;
    private final EmailService emailService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final VerifiableCredentialPolicyAuthorizationService verifiableCredentialPolicyAuthorizationService;
    private final TrustFrameworkService trustFrameworkService;
    private final LEARCredentialEmployeeFactory credentialEmployeeFactory;
    private final CredentialIssuerMetadataService credentialIssuerMetadataService;
    private final M2MTokenService m2mTokenService;
    private final CredentialDeliveryService credentialDeliveryService;

    @Override
    public Mono<Void> execute(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String token, String idToken) {

        // Check if the format is not "json_vc_jwt"
        if (!JWT_VC_JSON.equals(preSubmittedCredentialDataRequest.format())) {
            return Mono.error(new FormatUnsupportedException("Format: " + preSubmittedCredentialDataRequest.format() + " is not supported"));
        }
        // Check if operation_mode is different to sync
        if (!preSubmittedCredentialDataRequest.operationMode().equals(SYNC)) {
            return Mono.error(new OperationNotSupportedException("operation_mode: " + preSubmittedCredentialDataRequest.operationMode() + " with schema: " + preSubmittedCredentialDataRequest.schema()));
        }

        // Validate idToken header for VerifiableCertification schema
        if (preSubmittedCredentialDataRequest.schema().equals(LABEL_CREDENTIAL) && idToken == null) {
            return Mono.error(new MissingIdTokenHeaderException("Missing required ID Token header for VerifiableCertification issuance."));
        }

        // TODO LabelCredential the email information extraction must be done after the policy validation
        // We extract the email information from the PreSubmittedCredentialDataRequest
        CredentialOfferEmailNotificationInfo emailInfo =
                extractCredentialOfferEmailInfo(preSubmittedCredentialDataRequest);

        // Validate user policy before proceeding
        return verifiableCredentialPolicyAuthorizationService.authorize(token, preSubmittedCredentialDataRequest.schema(), preSubmittedCredentialDataRequest.payload(), idToken)
                .then(verifiableCredentialService.generateVc(processId, preSubmittedCredentialDataRequest, emailInfo.email())
                        .flatMap(transactionCode -> sendCredentialOfferEmail(transactionCode, emailInfo))
                );
    }

    private Mono<Void> sendCredentialOfferEmail(
            String transactionCode,
            CredentialOfferEmailNotificationInfo info
    ) {
        String credentialOfferUrl = buildCredentialOfferUrl(transactionCode);

        return emailService.sendCredentialActivationEmail(
                        info.email(),
                        CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                        credentialOfferUrl,
                        appConfig.getKnowledgebaseWalletUrl(),
                        info.user(),
                        info.organization()
                )
                .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    private String buildCredentialOfferUrl(String transactionCode) {
        return UriComponentsBuilder
                .fromHttpUrl(appConfig.getIssuerFrontendUrl())
                .path("/credential-offer")
                .queryParam("transaction_code", transactionCode)
                .build()
                .toUriString();
    }

    // Get the necessary information to send the credential offer email
    private CredentialOfferEmailNotificationInfo extractCredentialOfferEmailInfo(PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest) {
        String schema = preSubmittedCredentialDataRequest.schema();
        var payload = preSubmittedCredentialDataRequest.payload();


        return switch (schema) {
            case LEAR_CREDENTIAL_EMPLOYEE -> {
                String email = payload.get(MANDATEE).get(EMAIL).asText();
                String user  = payload.get(MANDATEE).get(FIRST_NAME).asText()
                        + " " + payload.get(MANDATEE).get(LAST_NAME).asText();
                String org   = payload.get(MANDATOR).get(ORGANIZATION).asText();
                yield new CredentialOfferEmailNotificationInfo(email, user, org);
            }
            case LEAR_CREDENTIAL_MACHINE -> {
                String email = payload.get(MANDATOR).get(EMAIL).asText();
                String org = payload.get(MANDATOR).get(ORGANIZATION).asText();
                String name = payload.get(MANDATOR).get(COMMON_NAME).asText();
                yield new CredentialOfferEmailNotificationInfo(email, name, org);
            }
            case LABEL_CREDENTIAL -> {
                    if(preSubmittedCredentialDataRequest.credentialOwnerEmail() == null || preSubmittedCredentialDataRequest.credentialOwnerEmail().isBlank()) {
                        throw new MissingEmailOwnerException("Email owner email is required for gx:LabelCredential schema");
                    }
                    String email = preSubmittedCredentialDataRequest.credentialOwnerEmail();
                yield new CredentialOfferEmailNotificationInfo(email, DEFAULT_USER_NAME, DEFAULT_ORGANIZATION_NAME);
            }
            default -> throw new FormatUnsupportedException(
                    "Unknown schema: " + schema
            );
        };
    }

    @Override
    public Mono<CredentialResponse> generateVerifiableCredentialResponse(
            String processId,
            CredentialRequest credentialRequest,
            String token) {

        return parseAuthServerNonce(token)
                .flatMap(nonce -> deferredCredentialMetadataService.getDeferredCredentialMetadataByAuthServerNonce(nonce)
                        .flatMap(deferred -> credentialProcedureService.getCredentialProcedureById(deferred.getProcedureId().toString())
                                .zipWhen(proc -> credentialIssuerMetadataService.getCredentialIssuerMetadata(processId))
                                .map(tuple -> Tuples.of(nonce, deferred, tuple.getT1(), tuple.getT2()))
                        )
                )
                .flatMap(tuple4 -> {
                    String nonce = tuple4.getT1();
                    DeferredCredentialMetadata deferredCredentialMetadata = tuple4.getT2();
                    CredentialProcedure proc = tuple4.getT3();
                    CredentialIssuerMetadata md = tuple4.getT4();

                    Mono<String> subjectDidMono = determineSubjectDid(proc, md, credentialRequest, token);

                    Mono<CredentialResponse> vcMono = subjectDidMono
                            .flatMap(did ->
                                        verifiableCredentialService.buildCredentialResponse(
                                                processId, did, nonce, token
                                        )
                            )
                            .switchIfEmpty(
                                    verifiableCredentialService.buildCredentialResponse(
                                            processId, null, nonce, token
                                    )
                            );

                    return vcMono.flatMap(cr ->
                            handleOperationMode(
                                    proc.getOperationMode(),
                                    processId,
                                    nonce,
                                    cr,
                                    proc,
                                    deferredCredentialMetadata
                            )
                    );
                });
    }

    private Mono<String> parseAuthServerNonce(String token) {
        return Mono.fromCallable(() -> {
                    JWSObject jws = JWSObject.parse(token);
                    return jws.getPayload().toJSONObject().get("jti").toString();
                })
                .onErrorMap(ParseException.class, e ->
                        new ParseErrorException("Error parsing accessToken")
                );
    }

    // This method determines the subject DID base on the credential type and proof provided in the request,
    // if proof is not needed it returns null.
    private Mono<String> determineSubjectDid(
            CredentialProcedure credentialProcedure,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest,
            String token) {

        final CredentialType typeEnum;
        try {
            typeEnum = CredentialType.valueOf(credentialProcedure.getCredentialType());
        } catch (IllegalArgumentException e) {
            return Mono.error(new FormatUnsupportedException(
                    "Unknown credential type: " + credentialProcedure.getCredentialType()));
        }

        return Mono.justOrEmpty(
                        metadata.credentialConfigurationsSupported().values().stream()
                                .filter(cfg ->
                                        cfg.credentialDefinition().type().contains(typeEnum.getTypeId())
                                )
                                .findFirst()
                )
                .switchIfEmpty(Mono.error(new FormatUnsupportedException(
                        "No configuration for typeId: " + typeEnum.getTypeId())))
                .flatMap(cfg -> {
                    boolean needsProof = cfg.cryptographicBindingMethodsSupported() != null
                            && !cfg.cryptographicBindingMethodsSupported().isEmpty();

                    if (!needsProof) {
                        return Mono.empty();
                    }

                    List<String> jwtList = credentialRequest.proofs() != null
                            ? credentialRequest.proofs().jwt()
                            : Collections.emptyList();

                    if (jwtList.isEmpty()) {
                        return Mono.error(new InvalidOrMissingProofException(
                                "Missing proof for type " + typeEnum.name()));
                    }

                    String jwtProof = jwtList.get(0);
                    return proofValidationService.isProofValid(jwtProof, token)
                            .flatMap(valid -> {
                                if (!Boolean.TRUE.equals(valid)) {
                                    return Mono.error(new InvalidOrMissingProofException("Invalid proof"));
                                }
                                return extractDidFromJwtProof(jwtProof);
                            });
                });
    }

    private Mono<CredentialResponse> handleOperationMode(
            String operationMode,
            String processId,
            String nonce,
            CredentialResponse cr,
            CredentialProcedure credentialProcedure,
            DeferredCredentialMetadata deferred
    ) {
        return switch (operationMode) {
            case ASYNC -> deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(nonce)
                    .flatMap(credentialProcedureService::getSignerEmailFromDecodedCredentialByProcedureId)
                    .flatMap(email -> emailService.sendPendingCredentialNotification(email, "Pending Credential")
                            .thenReturn(cr));
            case SYNC -> deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(nonce)
                    .flatMap(id -> credentialProcedureService.getCredentialStatusByProcedureId(id)
                            .flatMap(status -> {
                                Mono<Void> upd = !CredentialStatusEnum.PEND_SIGNATURE.toString().equals(status)
                                        ? credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(id)
                                        : Mono.empty();
                                return upd.then(credentialProcedureService.getDecodedCredentialByProcedureId(id));
                            })
                            .flatMap(decoded -> {
                                CredentialType typeEnum = CredentialType.valueOf(credentialProcedure.getCredentialType());
                                if (typeEnum == CredentialType.LEAR_CREDENTIAL_EMPLOYEE) {
                                    return getMandatorOrganizationIdentifier(processId, decoded);
                                }

                                if (deferred.getResponseUri() != null && !deferred.getResponseUri().isBlank()) {
                                    log.info("Sending VC to response URI: {}", deferred.getResponseUri());
                                    return m2mTokenService.getM2MToken()
                                            .flatMap(tokenResponse -> credentialDeliveryService.sendVcToResponseUri(deferred.getResponseUri(), decoded, credentialProcedure.getCredentialId().toString(),credentialProcedure.getOwnerEmail(),tokenResponse.accessToken()));
                                }

                                return Mono.empty();
                            })
                    )
                    .thenReturn(cr);
            default -> Mono.error(new IllegalArgumentException("Unknown operation mode: " + operationMode));
        };
    }

    @Override
    public Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, AuthServerNonceRequest authServerNonceRequest) {
        return verifiableCredentialService.bindAccessTokenByPreAuthorizedCode
                (processId, authServerNonceRequest.accessToken(), authServerNonceRequest.preAuthorizedCode());
    }

    @Override
    public Mono<DeferredCredentialResponse> generateVerifiableCredentialDeferredResponse(String processId, DeferredCredentialRequest deferredCredentialRequest) {
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

    private Mono<Void> getMandatorOrganizationIdentifier(String processId, String decodedCredential) {
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
