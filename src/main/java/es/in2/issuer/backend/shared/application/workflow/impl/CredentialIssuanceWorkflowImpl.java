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
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

import javax.naming.ConfigurationException;
import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.PEND_SIGNATURE;
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
    private final JwtUtils jwtUtils;

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
                String org   = payload.get(MANDATOR).get(ORGANIZATION).asText();
                yield new CredentialOfferEmailNotificationInfo(email, org);
            }
            case LEAR_CREDENTIAL_MACHINE -> {
                String email;
                if(preSubmittedCredentialDataRequest.email() == null || preSubmittedCredentialDataRequest.email().isBlank()) {
                    email = payload.get(MANDATOR).get(EMAIL).asText();
                    log.debug("No credential owner email found in presubmitted data. Using mandator email: {}", payload.get(MANDATOR).get(EMAIL).asText());
                } else {
                    email = preSubmittedCredentialDataRequest.email();
                }
                String org = payload.get(MANDATOR).get(ORGANIZATION).asText();
                yield new CredentialOfferEmailNotificationInfo(email, org);
            }
            case LABEL_CREDENTIAL -> {
                    if(preSubmittedCredentialDataRequest.email() == null || preSubmittedCredentialDataRequest.email().isBlank()) {
                        throw new MissingEmailOwnerException("Email owner email is required for gx:LabelCredential schema");
                    }
                    String email = preSubmittedCredentialDataRequest.email();
                yield new CredentialOfferEmailNotificationInfo(email, appConfig.getSysTenant());
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
            AccessTokenContext accessTokenContext) {
        log.debug("generateVerifiableCredentialResponse");
        log.info(
                "[{}] /credential request received: jti={}, credentialConfigurationId={}, hasProofJwt={}",
                processId,
                accessTokenContext.jti(),
                credentialRequest.credentialConfigurationId(),
                credentialRequest.proofs() != null && credentialRequest.proofs().jwt() != null && !credentialRequest.proofs().jwt().isEmpty()
        );

        return parseAuthServerNonce(accessTokenContext)
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
                    String email = proc.getUpdatedBy();
                    CredentialIssuerMetadata md = tuple4.getT4();
                    log.info(
                            "[{}] Loaded procedure context: nonce(jti)={}, operationMode={}, credentialType={}, responseUriPresent={}",
                            processId,
                            nonce,
                            proc.getOperationMode(),
                            proc.getCredentialType(),
                            deferredCredentialMetadata.getResponseUri() != null && !deferredCredentialMetadata.getResponseUri().isBlank()
                    );
                    log.debug("email (from udpatedBy): {}", email);

                    Mono<BindingInfo> bindingInfoMono  = determineBindingInfo(proc, md, credentialRequest, accessTokenContext).doOnNext(bi ->
                            log.info("[{}] Binding required -> subjectId={}, cnfType={}",
                                    processId,
                                    bi.subjectId(),
                                    bi.cnf() instanceof java.util.Map ? ((java.util.Map<?, ?>) bi.cnf()).keySet() : "unknown"
                            )
                    ).switchIfEmpty(Mono.fromRunnable(() ->
                            log.info("[{}] No cryptographic binding required for credentialType={}", processId, proc.getCredentialType())
                    ));


                    Mono<CredentialResponse> vcMono = bindingInfoMono
                            .flatMap(bindingInfo -> {
                                log.info("[{}] Building VC (binding) nonce={}", processId, nonce);
                                return verifiableCredentialService.buildCredentialResponse(
                                        processId,
                                        bindingInfo.subjectId(),
                                        nonce,
                                        accessTokenContext.rawToken(),
                                        email
                                );
                            })
                            .switchIfEmpty(Mono.defer(() -> {
                                log.info("[{}] Building VC (no binding) nonce={}", processId, nonce);
                                return verifiableCredentialService.buildCredentialResponse(
                                        processId, null, nonce, accessTokenContext.rawToken(), email
                                );
                            }));


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

    private Mono<String> parseAuthServerNonce(AccessTokenContext accessTokenContext) {
        log.debug(
                "Using auth_server_nonce (jti) from access token: {}",
                accessTokenContext.jti()
        );
        return Mono.just(accessTokenContext.jti());
    }



    private Mono<BindingInfo> determineBindingInfo(
            CredentialProcedure credentialProcedure,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext) {

        final CredentialType typeEnum;
        log.debug("determineBindingInfo: credentialType={}", credentialProcedure.getCredentialType());

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
                    var cryptoMethods = cfg.cryptographicBindingMethodsSupported();
                    boolean needsProof = cryptoMethods != null && !cryptoMethods.isEmpty();
                    log.info("Binding requirement for {}: needsProof={}", typeEnum.name(), needsProof);


                    if (!needsProof) {
                        return Mono.empty();
                    }

                    String cryptoBindingMethod = null;
                    try {
                        cryptoBindingMethod = cryptoMethods.stream()
                                .findFirst()
                                .orElseThrow(() -> new ConfigurationException(
                                        "No cryptographic binding method configured for " + typeEnum.name()
                                ));
                    } catch (ConfigurationException e) {
                        throw new RuntimeException(e);
                    }
                    log.debug("Crypto binding method for {}: {}", typeEnum.name(), cryptoBindingMethod);

                    var proofTypes = cfg.proofTypesSupported();
                    var jwtProofConfig = (proofTypes != null) ? proofTypes.get("jwt") : null;
                    Set<String> proofSigningAlgs = (jwtProofConfig != null)
                            ? jwtProofConfig.proofSigningAlgValuesSupported()
                            : null;

                    if (proofSigningAlgs == null || proofSigningAlgs.isEmpty()) {
                        return Mono.error(new ConfigurationException(
                                "No proof_signing_alg_values_supported configured for proof type 'jwt' " +
                                        "and credential type " + typeEnum.name()
                        ));
                    }
                    log.debug("Proof signing algs for {}: {}", typeEnum.name(), proofSigningAlgs);

                    List<String> jwtList = credentialRequest.proofs() != null
                            ? credentialRequest.proofs().jwt()
                            : Collections.emptyList();

                    if (jwtList.isEmpty()) {
                        return Mono.error(new InvalidOrMissingProofException(
                                "Missing proof for type " + typeEnum.name()));
                    }

                    String jwtProof = jwtList.get(0);

                    return proofValidationService
                            .isProofValid(jwtProof, accessTokenContext.rawToken(), proofSigningAlgs)
                            .flatMap(isValid -> {
                                if (!Boolean.TRUE.equals(isValid)) {
                                    return Mono.error(new InvalidOrMissingProofException("Invalid proof"));
                                }
                                return extractBindingInfoFromJwtProof(jwtProof);
                            })
                            .doOnNext(isValid -> log.info("Proof validation result for {}: {}", typeEnum.name(), isValid))
                            ;

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
        log.info(
                "[{}] handleOperationMode start: mode={}, nonce(jti)={}, credentialType={}, responseUriPresent={}",
                processId,
                operationMode,
                nonce,
                credentialProcedure.getCredentialType(),
                deferred.getResponseUri() != null && !deferred.getResponseUri().isBlank()
        );
        return switch (operationMode) {
            case ASYNC -> deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(nonce)
                    .flatMap(procId -> {
                        Mono<String> emailMono = Mono.fromCallable(() -> {
                            log.debug("Using procedure email for pending notification: {}", credentialProcedure.getEmail());
                            return credentialProcedure.getEmail();
                        });

                        return emailMono.flatMap(email ->
                                emailService
                                        .sendPendingCredentialNotification(email, "email.pending-credential")
                                        .thenReturn(cr)
                        );
                    });
            case SYNC -> deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(nonce)
                    .flatMap(id -> credentialProcedureService.getCredentialStatusByProcedureId(id)
                            .flatMap(status -> {
                                log.info("[{}] Current credential status for procedureId={}: {}", processId, id, status);

                                Mono<Void> upd = !PEND_SIGNATURE.toString().equals(status)
                                        ? credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(id)
                                        : Mono.empty();
                                boolean willUpdate = !PEND_SIGNATURE.equals(status);

                                log.info("[{}] SYNC: statusUpdateNeeded={} (status={})", processId, willUpdate, status);

                                return upd.then(credentialProcedureService.getDecodedCredentialByProcedureId(id)
                                        .zipWith(credentialProcedureService.getCredentialProcedureById(id)));
                            })
                            .flatMap(tuple -> {
                                String decoded = tuple.getT1();
                                CredentialProcedure updatedCredentialProcedure = tuple.getT2();

                                CredentialType typeEnum = CredentialType.valueOf(credentialProcedure.getCredentialType());
                                if (typeEnum == CredentialType.LEAR_CREDENTIAL_EMPLOYEE) {
                                    log.info("[{}] SYNC: LEAR_CREDENTIAL_EMPLOYEE -> running TrustFramework registration check", processId);

                                    return getMandatorOrganizationIdentifier(processId, decoded);
                                }

                                if (deferred.getResponseUri() != null && !deferred.getResponseUri().isBlank()) {
                                    String encodedCredential = updatedCredentialProcedure.getCredentialEncoded();
                                    if (encodedCredential == null || encodedCredential.isBlank()) {
                                        return Mono.error(new IllegalStateException("Encoded credential not found for procedureId: " + updatedCredentialProcedure.getProcedureId()));
                                    }

                                    log.info("Sending VC to response URI: {}", deferred.getResponseUri());
                                    return credentialProcedureService.getCredentialId(credentialProcedure)
                                            .doOnNext(credentialId -> log.debug("Using credentialId for delivery: {}", credentialId))
                                            .flatMap(credentialId ->
                                                    m2mTokenService.getM2MToken()
                                                            .flatMap(tokenResponse ->
                                                                    credentialDeliveryService.sendVcToResponseUri(
                                                                            deferred.getResponseUri(),
                                                                            encodedCredential,
                                                                            credentialId,
                                                                            credentialProcedure.getEmail(),
                                                                            tokenResponse.accessToken()
                                                                    )
                                                            )
                                            );
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

    public record BindingInfo(String subjectId, Object cnf) {}

    private Mono<BindingInfo> extractBindingInfoFromJwtProof(String jwtProof) {
        return Mono.fromCallable(() -> {
            JWSObject jws = JWSObject.parse(jwtProof);
            var header = jws.getHeader().toJSONObject();

            Object kid = header.get("kid");
            Object jwk = header.get("jwk");
            Object x5c = header.get("x5c");

            int count = (kid != null ? 1 : 0) + (jwk != null ? 1 : 0) + (x5c != null ? 1 : 0);
            log.debug("Proof header cnf fields present: kid={}, jwk={}, x5c={}, count={}",
                    kid != null, jwk != null, x5c != null, count);
            if (count != 1) {
                throw new IllegalArgumentException("Expected exactly one of kid/jwk/x5c in proof header");
            }

            String subjectId;
            if (kid != null) {
                String kidStr = kid.toString();
                subjectId = kidStr.contains("#") ? kidStr.split("#")[0] : kidStr;
                log.info("Binding extracted from proof: cnfType=kid, subjectId={}, kidPrefix={}",
                        subjectId,
                        kidStr.length() > 20 ? kidStr.substring(0, 20) : kidStr
                );

                return new BindingInfo(subjectId, java.util.Map.of("kid", kidStr));
            }
            if (jwk != null || x5c != null) {
                throw new IllegalArgumentException("Only kid-based binding is supported for now");
            }


            subjectId = null;
            return new BindingInfo(subjectId, java.util.Map.of("x5c", x5c));
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
