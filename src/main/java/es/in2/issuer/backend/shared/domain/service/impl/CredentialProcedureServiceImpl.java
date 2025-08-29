package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingCredentialTypeException;
import es.in2.issuer.backend.shared.domain.exception.NoCredentialFoundException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialProcedureServiceImpl implements CredentialProcedureService {

    private static final String UPDATED_CREDENTIAL = "Updated credential";
    private final CredentialProcedureRepository credentialProcedureRepository;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<String> createCredentialProcedure(CredentialProcedureCreationRequest credentialProcedureCreationRequest) {
        CredentialProcedure credentialProcedure = CredentialProcedure.builder()
                .credentialId(UUID.fromString(credentialProcedureCreationRequest.credentialId()))
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDecoded(credentialProcedureCreationRequest.credentialDecoded())
                .organizationIdentifier(credentialProcedureCreationRequest.organizationIdentifier())
                .credentialType(credentialProcedureCreationRequest.credentialType().toString())
                .subject(credentialProcedureCreationRequest.subject())
                .validUntil(credentialProcedureCreationRequest.validUntil())
                .updatedAt(new Timestamp(Instant.now().toEpochMilli()))
                .operationMode(credentialProcedureCreationRequest.operationMode())
                .signatureMode("remote")
                .ownerEmail(credentialProcedureCreationRequest.ownerEmail())
                .build();
        return credentialProcedureRepository.save(credentialProcedure)
                .map(savedCredentialProcedure -> savedCredentialProcedure.getProcedureId().toString())
                .doOnError(e -> log.error("Error saving credential procedure", e));
    }

    @Override
    public Mono<String> getCredentialTypeByProcedureId(String procedureId) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(this::getCredentialType);
    }

    private Mono<String> getCredentialType(CredentialProcedure credentialProcedure) {
        try {
            JsonNode credential = objectMapper.readTree(credentialProcedure.getCredentialDecoded());
            JsonNode typeNode = credential.has(VC) ? credential.get(VC).get(TYPE) : credential.get(TYPE);

            return extractCredentialType(typeNode)
                    .map(Mono::just)
                    .orElseGet(Mono::empty);
        } catch (JsonProcessingException e) {
            return Mono.error(new ParseCredentialJsonException("Error parsing credential"));
        }
    }

    private Optional<String> extractCredentialType(JsonNode typeNode) {
        if (typeNode == null || !typeNode.isArray()) {
            throw new MissingCredentialTypeException("The credential type is missing");
        }

        for (JsonNode type : typeNode) {
            String typeText = type.asText();
            if (!typeText.equals(VERIFIABLE_CREDENTIAL) && !typeText.equals(VERIFIABLE_ATTESTATION)) {
                return Optional.of(typeText);
            }
        }

        return Optional.empty();
    }

    @Override
    public Mono<Void> updateDecodedCredentialByProcedureId(String procedureId, String credential, String format) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    credentialProcedure.setCredentialDecoded(credential);
                    credentialProcedure.setCredentialStatus(CredentialStatusEnum.ISSUED);
                    credentialProcedure.setCredentialFormat(format);
                    credentialProcedure.setUpdatedAt(new Timestamp(Instant.now().toEpochMilli()));

                    return credentialProcedureRepository.save(credentialProcedure)
                            .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                            .then();
                });
    }

    @Override
    public Mono<Void> updateDecodedCredentialByProcedureId(String procedureId, String credential) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    credentialProcedure.setCredentialDecoded(credential);
                    credentialProcedure.setCredentialStatus(CredentialStatusEnum.ISSUED);
                    credentialProcedure.setUpdatedAt(new Timestamp(Instant.now().toEpochMilli()));

                    return credentialProcedureRepository.save(credentialProcedure)
                            .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                            .then();
                });
    }

    @Override
    public Mono<String> getDecodedCredentialByProcedureId(String procedureId) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> Mono.just(credentialProcedure.getCredentialDecoded()));
    }

    @Override
    public Mono<CredentialProcedure> getCredentialByCredentialId(String credentialId) {
        return credentialProcedureRepository.findByCredentialId(UUID.fromString(credentialId));
    }

    @Override
    public Mono<String> getOperationModeByProcedureId(String procedureId) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> Mono.just(credentialProcedure.getOperationMode()));
    }

    @Override
    public Mono<String> getCredentialStatusByProcedureId(String procedureId) {
        log.debug("Getting credential status for procedureId: {}", procedureId);
        return credentialProcedureRepository.findCredentialStatusByProcedureId(UUID.fromString(procedureId));
    }

    //TODO Ajustar estos if-else cuando quede claro que hacer con el mail de jesús y cuando la learemployee v1 ya no exista y el de la certificación arreglarlo
    @Override
    public Mono<String> getSignerEmailFromDecodedCredentialByProcedureId(String procedureId) {
        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    try {
                        JsonNode credential = objectMapper.readTree(credentialProcedure.getCredentialDecoded());
                        return switch (credentialProcedure.getCredentialType()) {
                            case LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE -> {
                                if (credential.has(VC)) {
                                    JsonNode vcNode = credential.get(VC);
                                    JsonNode mandateNode = vcNode.get(CREDENTIAL_SUBJECT).get(MANDATE);
                                    if (mandateNode.has(SIGNER)) {
                                        yield Mono.just(mandateNode.get(SIGNER).get(EMAIL_ADDRESS).asText());
                                    } else {
                                        yield Mono.just(vcNode.get(ISSUER).get(EMAIL_ADDRESS).asText());
                                    }
                                } else {
                                    JsonNode mandatorEmailNode = credential.get(CREDENTIAL_SUBJECT).get(MANDATE).get(MANDATOR).get(EMAIL_ADDRESS);
                                    String email = mandatorEmailNode.asText();
                                    yield Mono.just(email.equals("jesus.ruiz@in2.es") ? "domesupport@in2.es" : email);
                                }
                            }
                            case LABEL_CREDENTIAL_TYPE -> Mono.just("domesupport@in2.es");

                            case LEAR_CREDENTIAL_MACHINE_TYPE ->
                                Mono.just(credential
                                        .get(CREDENTIAL_SUBJECT)
                                        .get(MANDATE)
                                        .get(MANDATOR)
                                        .get(EMAIL)
                                        .asText());


                            default ->
                                    Mono.error(new IllegalArgumentException("Unsupported credential type: " + credentialProcedure.getCredentialType()));
                        };
                    } catch (JsonProcessingException e) {
                        return Mono.error(new RuntimeException());
                    }

                });
    }

    @Override
    public Flux<String> getAllIssuedCredentialByOrganizationIdentifier(String organizationIdentifier) {
        return credentialProcedureRepository.findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum.ISSUED, organizationIdentifier)
                .map(CredentialProcedure::getCredentialDecoded);
    }

    @Override
    public Mono<CredentialDetails> getProcedureDetailByProcedureIdAndOrganizationId(String
                                                                                            organizationIdentifier, String procedureId) {
        return credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(UUID.fromString(procedureId), organizationIdentifier)
                .switchIfEmpty(Mono.error(new NoCredentialFoundException("No credential found for procedureId: " + procedureId)))
                .flatMap(credentialProcedure -> {
                    try {
                        log.info("Found credential: {}", credentialProcedure);
                        return Mono.just(CredentialDetails.builder()
                                .procedureId(credentialProcedure.getProcedureId())
                                .lifeCycleStatus(String.valueOf(credentialProcedure.getCredentialStatus()))
                                .operationMode(credentialProcedure.getOperationMode())
                                .signatureMode(credentialProcedure.getSignatureMode())
                                .credential(objectMapper.readTree(credentialProcedure.getCredentialDecoded()))
                                .build());
                    } catch (JsonProcessingException e) {
                        log.warn(PARSING_CREDENTIAL_ERROR_MESSAGE, e);
                        return Mono.error(new JsonParseException(null, PARSING_CREDENTIAL_ERROR_MESSAGE));
                    }
                })
                .doOnError(error -> log.error("Could not load credentials, error: {}", error.getMessage()));
    }

    @Override
    public Mono<String> updatedEncodedCredentialByCredentialId(String encodedCredential, String
            credentialId) {
        return getCredentialByCredentialId(credentialId)
                .flatMap(credentialProcedure -> {
                    credentialProcedure.setCredentialEncoded(encodedCredential);
                    return credentialProcedureRepository.save(credentialProcedure)
                            .then(Mono.just(credentialProcedure.getProcedureId().toString()));
                });
    }

    @Override
    public Mono<Void> updateCredentialProcedureCredentialStatusToValidByProcedureId(String procedureId) {
        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    log.debug("Updating credential {} status to valid for procedureId: {}", credentialProcedure, procedureId);
                    credentialProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
                    return credentialProcedureRepository.save(credentialProcedure)
                            .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL, "credentialProcedure: " + credentialProcedure))
                            .then();
                });
    }

    @Override
    public Mono<Void> updateCredentialProcedureCredentialStatusToRevoke(CredentialProcedure
                                                                                credentialProcedure) {
        credentialProcedure.setCredentialStatus(CredentialStatusEnum.REVOKED);
        credentialProcedure.setUpdatedAt(Timestamp.from(Instant.now()));
        return credentialProcedureRepository.save(credentialProcedure)
                .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                .then();
    }

    @Override
    public Mono<CredentialProcedures> getAllProceduresBasicInfoByOrganizationId(String
                                                                                        organizationIdentifier) {
        return credentialProcedureRepository.findAllByOrganizationIdentifier(organizationIdentifier)
                .flatMap(credentialProcedure ->
                        getCredentialTypeByProcedureId(String.valueOf(credentialProcedure.getProcedureId()))
                                .flatMap(credentialType ->
                                        Mono.just(ProcedureBasicInfo.builder()
                                                .procedureId(credentialProcedure.getProcedureId())
                                                .subject(credentialProcedure.getSubject())
                                                .credentialType(credentialProcedure.getCredentialType())
                                                .status(String.valueOf(credentialProcedure.getCredentialStatus()))
                                                .updated(credentialProcedure.getUpdatedAt())
                                                .build())))
                .map(procedureBasicInfo ->
                        CredentialProcedures.CredentialProcedure.builder()
                                .credentialProcedure(procedureBasicInfo)
                                .build())
                .collectList()
                .map(CredentialProcedures::new);
    }

    @Override
    public Mono<CredentialProcedure> getCredentialProcedureById(String procedureId) {
        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId));
    }

    @Override
    public Mono<Void> updateFormatByProcedureId(String procedureId, String format) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    credentialProcedure.setCredentialFormat(format);
                    return credentialProcedureRepository.save(credentialProcedure)
                            .doOnSuccess(result -> log.info("Updated format for procedureId: {}", procedureId))
                            .then();
                });
    }

    @Override
    public Mono<CredentialOfferEmailNotificationInfo> getEmailCredentialOfferInfoByProcedureId(String
                                                                                                       procedureId) {
        return credentialProcedureRepository
                .findByProcedureId(UUID.fromString(procedureId))
                .flatMap(credentialProcedure ->
                        switch (credentialProcedure.getCredentialType()) {
                            case LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE -> Mono.fromCallable(() ->
                                            objectMapper.readTree(credentialProcedure.getCredentialDecoded())
                                    )
                                    .map(credential -> {
                                        String user = credentialProcedure.getSubject();
                                        String org = credential
                                                .get(CREDENTIAL_SUBJECT)
                                                .get(MANDATE)
                                                .get(MANDATOR)
                                                .get(ORGANIZATION)
                                                .asText();
                                        return new CredentialOfferEmailNotificationInfo(
                                                credentialProcedure.getOwnerEmail(),
                                                user,
                                                org
                                        );
                                    })
                                    .onErrorMap(JsonProcessingException.class, e ->
                                            new ParseCredentialJsonException(
                                                    "Error parsing credential for procedureId: " + procedureId
                                            )
                                    );
                            case LEAR_CREDENTIAL_MACHINE_TYPE -> Mono.fromCallable(() ->
                                            objectMapper.readTree(credentialProcedure.getCredentialDecoded())
                                    )
                                    .map(credential -> {
                                        JsonNode mandator = credential
                                                .get(CREDENTIAL_SUBJECT)
                                                .get(MANDATE)
                                                .get(MANDATOR);
                                        String user = mandator
                                                .get(COMMON_NAME)
                                                .asText();
                                        String org = mandator
                                                .get(ORGANIZATION)
                                                .asText();
                                        String email = mandator
                                                .get(EMAIL)
                                                .asText();
                                        return new CredentialOfferEmailNotificationInfo(
                                                email,
                                                user,
                                                org
                                        );
                                    })
                                    .onErrorMap(JsonProcessingException.class, e ->
                                            new ParseCredentialJsonException(
                                                    "Error parsing credential for procedureId: " + procedureId
                                            )
                                    );
                            case LABEL_CREDENTIAL_TYPE -> Mono.just(
                                    new CredentialOfferEmailNotificationInfo(
                                            credentialProcedure.getOwnerEmail(),
                                            DEFAULT_USER_NAME,
                                            DEFAULT_ORGANIZATION_NAME
                                    )
                            );
                            default -> Mono.error(new FormatUnsupportedException(
                                    "Unknown credential type: " + credentialProcedure.getCredentialType()
                            ));
                        });
    }

}
