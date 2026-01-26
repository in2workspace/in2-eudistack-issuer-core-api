package es.in2.issuer.backend.shared.application.workflow.impl;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.exception.Base45Exception;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureInvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.Issuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.LabelCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.spi.CredentialStatusAllocator;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.minvws.encoding.Base45;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.function.Tuples;

import java.io.ByteArrayOutputStream;
import java.util.*;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CWT_VC;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.JWT_VC;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialSignerWorkflowImpl implements CredentialSignerWorkflow {

    private final AccessTokenService accessTokenService;
    private final BackofficePdpService backofficePdpService;
    private final AppConfig appConfig;
    private final DeferredCredentialWorkflow deferredCredentialWorkflow;
    private final RemoteSignatureService remoteSignatureService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    private final LEARCredentialMachineFactory learCredentialMachineFactory;
    private final LabelCredentialFactory labelCredentialFactory;
    private final CredentialProcedureRepository credentialProcedureRepository;
    private final CredentialProcedureService credentialProcedureService;
    private final M2MTokenService m2mTokenService;
    private final CredentialDeliveryService credentialDeliveryService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final IssuerFactory issuerFactory;
    private final CredentialStatusAllocator credentialStatusAllocator;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<String> signAndUpdateCredentialByProcedureId(String processId, String token, String procedureId, String format, String mandateeEmail) {
        log.debug(
                "Starting credential signing and update [processId={}, procedureId={}, format={}, mandateeEmail={}]",
                processId,
                procedureId,
                format,
                mandateeEmail
        );

        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                .switchIfEmpty(Mono.error(new CredentialProcedureNotFoundException(
                        "Credential procedure with ID " + procedureId + " was not found"
                )))
                .flatMap(proc -> {
                    String signerEmail = (mandateeEmail != null && !mandateeEmail.isBlank())
                            ? mandateeEmail
                            : proc.getUpdatedBy();
                    return bindIssuerAndStatusIntoDecodedCredential(proc, procedureId, token, signerEmail)
                            .flatMap(updatedDecoded ->
                                    credentialProcedureService
                                            .updateDecodedCredentialByProcedureId(procedureId, updatedDecoded, JWT_VC)
                                            .thenReturn(updatedDecoded)
                            )
                            .flatMap(updatedDecoded -> buildUnsignedPayloadFromDecoded(proc.getCredentialType(), updatedDecoded))
                            .flatMap(unsignedPayload ->
                                    signCredentialOnRequestedFormat(unsignedPayload, format, token, procedureId, signerEmail)
                            );
                })
                .flatMap(signedCredential ->
                        updateSignedCredential(signedCredential, procedureId)
                                .thenReturn(signedCredential)
                )
                .doOnSuccess(x -> log.info("Credential Signed and updated successfully."));
    }

    private Mono<String> bindIssuerAndStatusIntoDecodedCredential(
            CredentialProcedure proc,
            String procedureId,
            String token,
            String mandateeEmail
    ) {
        String credentialType = proc.getCredentialType();
        log.info("CredentialSignerWorkflowImpl - bindIssuerAndStatusIntoDecodedCredential");
        log.info("CP: {}, procedureId: {}, token: {}, mandateeEmail: {}", proc, procedureId, token, mandateeEmail);

        return resolveIssuerForType(credentialType, procedureId, mandateeEmail)
                .switchIfEmpty(Mono.error(new IllegalStateException(
                        "Issuer could not be resolved for procedureId: " + procedureId
                )))
                .flatMap(issuer -> {
                    String issuerId = issuer.getId();
                    return credentialStatusAllocator
                            .allocate(issuerId, procedureId, token)
                            .map(credentialStatus -> Tuples.of(issuer, credentialStatus));
                })
                .flatMap(tuple -> {
                    Issuer issuer = tuple.getT1();
                    CredentialStatus credentialStatus = tuple.getT2();
                    return injectIssuerAndCredentialStatus(proc.getCredentialDecoded(), issuer, credentialStatus);
                });
    }

    private Mono<Issuer> resolveIssuerForType(String credentialType, String procedureId, String mandateeEmail) {
        if (LABEL_CREDENTIAL_TYPE.equals(credentialType)) {
            return issuerFactory.createSimpleIssuer(procedureId, mandateeEmail).cast(Issuer.class);
        }
        return issuerFactory.createDetailedIssuer(procedureId, mandateeEmail).cast(Issuer.class);
    }

    private Mono<String> injectIssuerAndCredentialStatus(String decodedCredential, Issuer issuer, CredentialStatus credentialStatus) {
        return Mono.fromCallable(() -> {
            JsonNode rootNode = objectMapper.readTree(decodedCredential);
            if (!(rootNode instanceof ObjectNode root)) {
                throw new IllegalArgumentException("credentialDecoded must be a JSON object");
            }

            // Inject issuer (full object, because your models use issuer object)
            root.set("issuer", objectMapper.valueToTree(issuer));

            // Inject credentialStatus
            root.set("credentialStatus", objectMapper.valueToTree(credentialStatus));

            return objectMapper.writeValueAsString(root);
        });
    }

    private Mono<String> buildUnsignedPayloadFromDecoded(String credentialType, String updatedDecodedCredential) {
        try {
            log.info("Building JWT payload for credential signing for credential with type: {}", credentialType);

            return switch (credentialType) {
                case LABEL_CREDENTIAL_TYPE -> {
                    LabelCredential labelCredential = labelCredentialFactory.mapStringToLabelCredential(updatedDecodedCredential);
                    yield labelCredentialFactory.buildLabelCredentialJwtPayload(labelCredential)
                            .flatMap(labelCredentialFactory::convertLabelCredentialJwtPayloadInToString);
                }
                case LEAR_CREDENTIAL_EMPLOYEE_TYPE -> {
                    LEARCredentialEmployee learCredentialEmployee = learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(updatedDecodedCredential);
                    yield learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(learCredentialEmployee)
                            .flatMap(learCredentialEmployeeFactory::convertLEARCredentialEmployeeJwtPayloadInToString);
                }
                case LEAR_CREDENTIAL_MACHINE_TYPE -> {
                    LEARCredentialMachine learCredentialMachine = learCredentialMachineFactory.mapStringToLEARCredentialMachine(updatedDecodedCredential);
                    yield learCredentialMachineFactory.buildLEARCredentialMachineJwtPayload(learCredentialMachine)
                            .flatMap(learCredentialMachineFactory::convertLEARCredentialMachineJwtPayloadInToString);
                }
                default -> {
                    log.error("Unsupported credential type: {}", credentialType);
                    yield Mono.error(new IllegalArgumentException("Unsupported credential type: " + credentialType));
                }
            };
        } catch (Exception e) {
            log.error("Error building unsigned payload - {}", e.getMessage(), e);
            return Mono.error(new IllegalArgumentException("Error building unsigned payload"));
        }
    }

    private Mono<Void> updateSignedCredential(String signedCredential, String procedureId) {
        List<SignedCredentials.SignedCredential> credentials = List.of(SignedCredentials.SignedCredential.builder().credential(signedCredential).build());
        SignedCredentials signedCredentials = new SignedCredentials(credentials);
        return deferredCredentialWorkflow.updateSignedCredentials(signedCredentials, procedureId);
    }

    private Mono<String> signCredentialOnRequestedFormat(String unsignedCredential, String format, String token, String procedureId, String email) {
        return Mono.defer(() -> {
            if (format.equals(JWT_VC)) {
                log.debug("Credential Payload {}", unsignedCredential);
                log.info("Signing credential in JADES remotely ...");
                SignatureRequest signatureRequest = new SignatureRequest(
                        new SignatureConfiguration(SignatureType.JADES, Collections.emptyMap()),
                        unsignedCredential
                );

                return remoteSignatureService.signIssuedCredential(signatureRequest, token, procedureId, email)
                        .doOnSubscribe(s -> {
                        })
                        .doOnNext(data -> {
                        })
                        .publishOn(Schedulers.boundedElastic())
                        .map(SignedData::data)
                        .doOnSuccess(result -> {
                        })
                        .doOnError(e -> {
                        });
            } else if (format.equals(CWT_VC)) {
                log.info(unsignedCredential);
                return generateCborFromJson(unsignedCredential)
                        .flatMap(cbor -> generateCOSEBytesFromCBOR(cbor, token, email))
                        .flatMap(this::compressAndConvertToBase45FromCOSE);
            } else {
                return Mono.error(new IllegalArgumentException("Unsupported credential format: " + format));
            }
        });
    }

    /**
     * Generate CBOR payload for COSE.
     *
     * @param edgcJson EDGC payload as JSON string
     * @return Mono emitting CBOR bytes
     */
    private Mono<byte[]> generateCborFromJson(String edgcJson) {
        return Mono.fromCallable(() -> CBORObject.FromJSONString(edgcJson).EncodeToBytes());
    }

    /**
     * Generate COSE bytes from CBOR bytes.
     *
     * @param cbor  CBOR bytes
     * @param token Authentication token
     * @return Mono emitting COSE bytes
     */
    private Mono<byte[]> generateCOSEBytesFromCBOR(byte[] cbor, String token, String email) {
        log.info("Signing credential in COSE format remotely ...");
        String cborBase64 = Base64.getEncoder().encodeToString(cbor);
        SignatureRequest signatureRequest = new SignatureRequest(
                new SignatureConfiguration(SignatureType.COSE, Collections.emptyMap()),
                cborBase64
        );
        return remoteSignatureService.signIssuedCredential(signatureRequest, token, "", email).map(signedData -> Base64.getDecoder().decode(signedData.data()));
    }

    /**
     * Compress COSE bytes and convert it to Base45.
     *
     * @param cose COSE Bytes
     * @return Mono emitting COSE bytes compressed and in Base45
     */
    private Mono<String> compressAndConvertToBase45FromCOSE(byte[] cose) {
        return Mono.fromCallable(() -> {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            try (CompressorOutputStream deflateOut = new CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, stream)) {
                deflateOut.write(cose);
            } // Automatically closed by try-with-resources
            byte[] zip = stream.toByteArray();
            return Base45.getEncoder().encodeToString(zip);
        }).onErrorResume(e -> {
            log.error("Error compressing and converting to Base45: " + e.getMessage(), e);
            return Mono.error(new Base45Exception("Error compressing and converting to Base45"));
        });
    }

    @Override
    public Mono<Void> retrySignUnsignedCredential(String processId, String authorizationHeader, String procedureId) {
        log.info("Retrying to sign credential. processId={} procedureId={}", processId, procedureId);

        UUID uuid = UUID.fromString(procedureId);

        return credentialProcedureRepository.findByProcedureId(uuid)
                .switchIfEmpty(Mono.error(new CredentialProcedureNotFoundException(
                        "Credential procedure with ID " + procedureId + " was not found"
                )))
                .doOnNext(credentialProcedure ->
                        log.info("ProcessID: {} - Current credential status: {}",
                                processId, credentialProcedure.getCredentialStatus())
                )
                .flatMap(credentialProcedure ->
                        accessTokenService.getCleanBearerToken(authorizationHeader)
                                .flatMap(token ->
                                        backofficePdpService
                                                .validateSignCredential(processId, token, credentialProcedure)
                                                .thenReturn(token)
                                )
                                .zipWhen(t -> accessTokenService.getMandateeEmail(authorizationHeader))
                                .flatMap(tupleTokenEmail -> {
                                    String token = tupleTokenEmail.getT1();
                                    String email = tupleTokenEmail.getT2();

                                    return this.signAndUpdateCredentialByProcedureId(
                                                    processId,
                                                    token,
                                                    procedureId,
                                                    JWT_VC,
                                                    email
                                            )
                                            .flatMap(signedVc ->
                                                    credentialProcedureService
                                                            .updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId)
                                                            .thenReturn(signedVc)
                                            )
                                            .flatMap(signedVc ->
                                                    credentialProcedureRepository.findByProcedureId(uuid)
                                                            .flatMap(updatedCredentialProcedure -> {
                                                                String credentialType = updatedCredentialProcedure.getCredentialType();
                                                                if (!LABEL_CREDENTIAL_TYPE.equals(credentialType)) {
                                                                    return Mono.empty();
                                                                }

                                                                return deferredCredentialMetadataService
                                                                        .getResponseUriByProcedureId(procedureId)
                                                                        .switchIfEmpty(Mono.error(new IllegalStateException(
                                                                                "Missing responseUri for procedureId: " + procedureId
                                                                        )))
                                                                        .flatMap(responseUri -> {
                                                                            try {
                                                                                String companyEmail = updatedCredentialProcedure.getEmail();

                                                                                return credentialProcedureService
                                                                                        .getCredentialId(updatedCredentialProcedure)
                                                                                        .flatMap(credentialId ->
                                                                                                m2mTokenService.getM2MToken()
                                                                                                        .flatMap(m2mToken ->
                                                                                                                credentialDeliveryService.sendVcToResponseUri(
                                                                                                                        responseUri,
                                                                                                                        signedVc,
                                                                                                                        credentialId,
                                                                                                                        companyEmail,
                                                                                                                        m2mToken.accessToken()
                                                                                                                )
                                                                                                        )
                                                                                        );
                                                                            } catch (Exception e) {
                                                                                log.error("Error preparing signed VC for delivery", e);
                                                                                return Mono.error(new RuntimeException(
                                                                                        "Failed to prepare signed VC for delivery", e
                                                                                ));
                                                                            }
                                                                        });
                                                            })
                                            );
                                })
                )
                .then();
    }


    private Mono<Void> updateDecodedCredentialByProcedureId(String procedureId, String bindCredential) {
        log.info("ProcessID: {} - Credential mapped and bound to the issuer: {}", procedureId, bindCredential);
        return credentialProcedureService.updateDecodedCredentialByProcedureId(
                procedureId,
                bindCredential,
                JWT_VC
        );
    }

    private CredentialStatus toCredentialStatus(Map<String, Object> map) {
        // Defensive checks
        Object type = map.get("type");
        Object id = map.get("id");
        Object purpose = map.get("statusPurpose");
        Object idx = map.get("statusListIndex");
        Object list = map.get("statusListCredential");

        if (!(type instanceof String) || !(id instanceof String) || !(purpose instanceof String) || list == null) {
            throw new IllegalArgumentException("Invalid credentialStatus map");
        }

        return CredentialStatus.builder()
                .id((String) id)
                .type((String) type)
                .statusPurpose((String) purpose)
                .statusListIndex(String.valueOf(idx)) // idx pot ser Integer
                .statusListCredential(String.valueOf(list))
                .build();
    }
}
