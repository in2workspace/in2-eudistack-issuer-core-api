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
import java.util.UUID;

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
            AccessTokenContext accessTokenContext
    ) {

        final String nonce = accessTokenContext.jti();
        final String procedureId = accessTokenContext.procedureId();

        return credentialProcedureService.getCredentialProcedureById(procedureId)
                .zipWhen(proc -> credentialIssuerMetadataService.getCredentialIssuerMetadata(processId))
                .flatMap(tuple -> {
                    CredentialProcedure proc = tuple.getT1();
                    CredentialIssuerMetadata md = tuple.getT2();

                    String email = proc.getEmail();

                    boolean responseUriPresent = accessTokenContext.responseUri() != null && !accessTokenContext.responseUri().isBlank();

                    log.info(
                            "[{}] Loaded procedure context: nonce(jti)={}, procedureId={}, operationMode={}, credentialType={}, responseUriPresent={}",
                            processId,
                            nonce,
                            procedureId,
                            proc.getOperationMode(),
                            proc.getCredentialType(),
                            responseUriPresent
                    );

                    Mono<BindingInfo> bindingInfoMono = validateAndDetermineBindingInfo(proc, md, credentialRequest)
                                    .doOnNext(bi -> log.info(
                                            "[{}] Binding required -> subjectId={}, cnfKeys={}",
                                            processId,
                                            bi.subjectId(),
                                            (bi.cnf() instanceof java.util.Map<?, ?> m) ? m.keySet() : "unknown"
                                    ))
                                    .doOnSuccess(bi -> {
                                        if (bi == null) {
                                            log.info("[{}] No cryptographic binding required for credentialType={}",
                                                    processId, proc.getCredentialType());
                                        }
                                    });

                    Mono<CredentialResponse> vcMono = bindingInfoMono
                            .flatMap(bi -> verifiableCredentialService.buildCredentialResponse(
                                    processId,
                                    bi.subjectId(),
                                    nonce,
                                    accessTokenContext.rawToken(),
                                    email,
                                    procedureId
                            ))
                            .switchIfEmpty(Mono.defer(() -> verifiableCredentialService.buildCredentialResponse(
                                    processId,
                                    null,
                                    nonce,
                                    accessTokenContext.rawToken(),
                                    email,
                                    procedureId
                            )));

                    DeferredCredentialMetadata deferred = new DeferredCredentialMetadata();
                    deferred.setResponseUri(accessTokenContext.responseUri());
                    deferred.setProcedureId(UUID.fromString(procedureId));

                    return vcMono.flatMap(cr ->
                            handleOperationMode(
                                    proc.getOperationMode(),
                                    processId,
                                    nonce,
                                    cr,
                                    proc,
                                    deferred
                            )
                    );
                });
    }

    private Mono<BindingInfo> validateAndDetermineBindingInfo(
            CredentialProcedure credentialProcedure,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest
    ) {

        //Resolve the credential type declared in the procedure
        final CredentialType typeEnum;
        log.debug("validateAndDetermineBindingInfo: credentialType={}", credentialProcedure.getCredentialType());

        try {
            typeEnum = CredentialType.valueOf(credentialProcedure.getCredentialType());
        } catch (IllegalArgumentException e) {
            return Mono.error(new FormatUnsupportedException(
                    "Unknown credential type: " + credentialProcedure.getCredentialType()));
        }

        //Find the Issuer configuration that matches this credential type
        return Mono.justOrEmpty(
                        metadata.credentialConfigurationsSupported()
                                .values()
                                .stream()
                                .filter(cfg ->
                                        cfg.credentialDefinition().type().contains(typeEnum.getTypeId())
                                )
                                .findFirst()
                )
                .switchIfEmpty(Mono.error(new FormatUnsupportedException(
                        "No configuration for typeId: " + typeEnum.getTypeId()
                )))

                //Evaluate cryptographic binding requirements
                .flatMap(cfg -> {

                    //crypto binding methods configured by the Issuer
                    var cryptoMethods = cfg.cryptographicBindingMethodsSupported();

                    boolean needsProof = cryptoMethods != null && !cryptoMethods.isEmpty();
                    log.info("Binding requirement for {}: needsProof={}", typeEnum.name(), needsProof);

                    //If no cryptographic binding is required
                    if (!needsProof) {
                        return Mono.empty();
                    }

                    //Select the cryptographic binding method
                    String cryptoBindingMethod;
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

                    //Resolve proof configuration for JWT proofs
                    var proofTypes = cfg.proofTypesSupported();
                    var jwtProofConfig = (proofTypes != null) ? proofTypes.get("jwt") : null;

                    //Allowed signing algorithms for the JWT proof
                    Set<String> proofSigningAlgoritms = (jwtProofConfig != null) ? jwtProofConfig.proofSigningAlgValuesSupported() : null;

                    //Fail if the Issuer configuration is incomplete
                    if (proofSigningAlgoritms == null || proofSigningAlgoritms.isEmpty()) {
                        return Mono.error(new ConfigurationException(
                                "No proof_signing_alg_values_supported configured for proof type 'jwt' " +
                                        "and credential type " + typeEnum.name()
                        ));
                    }

                    log.debug("Proof signing algs for {}: {}", typeEnum.name(), proofSigningAlgoritms);

                    //Extract the proof(s) provided by the wallet
                    List<String> jwtList = credentialRequest.proofs() != null
                            ? credentialRequest.proofs().jwt()
                            : Collections.emptyList();

                    //Wallet did not provide a proof although it is required
                    if (jwtList.isEmpty()) {
                        return Mono.error(new InvalidOrMissingProofException(
                                "Missing proof for type " + typeEnum.name()
                        ));
                    }

                    //Currently only the first proof is used
                    String jwtProof = jwtList.get(0);
                    String expectedAudience = metadata.credentialIssuer();

                    //Validate the proof according to Issuer configuration
                    return proofValidationService
                            .isProofValid(
                                    jwtProof,
                                    proofSigningAlgoritms,
                                    expectedAudience
                            )
                            .doOnNext(valid ->
                                    log.info("Proof validation result for {}: {}", typeEnum.name(), valid)
                            )

                            //If the proof is invalid, reject the request
                            .flatMap(valid -> {
                                if (!Boolean.TRUE.equals(valid)) {
                                    return Mono.error(new InvalidOrMissingProofException("Invalid proof"));
                                }

                                //Extract binding information from the JWT proof
                                return extractBindingInfoFromJwtProof(jwtProof);
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
        log.info(
                "[{}] handleOperationMode start: mode={}, nonce(jti)={}, credentialType={}, responseUriPresent={}",
                processId,
                operationMode,
                nonce,
                credentialProcedure.getCredentialType(),
                deferred.getResponseUri() != null && !deferred.getResponseUri().isBlank()
        );
        return switch (operationMode) {
            case ASYNC -> {
                Mono<String> emailMono = Mono.just(credentialProcedure.getEmail());
                yield emailMono.flatMap(email ->
                        emailService.sendPendingCredentialNotification(email, "email.pending-credential")
                                .thenReturn(cr)
                );
            }
            case SYNC -> Mono.just(credentialProcedure)
                    .flatMap(proc -> credentialProcedureService.getCredentialStatusByProcedureId(proc.getProcedureId().toString())
                            .flatMap(status -> {
                                Mono<Void> upd = !PEND_SIGNATURE.toString().equals(status)
                                        ? credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(proc.getProcedureId().toString())
                                        : Mono.empty();

                                return upd.then(credentialProcedureService.getDecodedCredentialByProcedureId(proc.getProcedureId().toString())
                                        .zipWith(credentialProcedureService.getCredentialProcedureById(proc.getProcedureId().toString())));
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
