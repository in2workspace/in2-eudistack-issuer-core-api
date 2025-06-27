package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LabelCredentialJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.LabelCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.infrastructure.config.DefaultSignerConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL_CONTEXT;
import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL_TYPES;

@Component
@RequiredArgsConstructor
@Slf4j
public class LabelCredentialFactory {
    private final DefaultSignerConfig defaultSignerConfig;
    private final ObjectMapper objectMapper;
    private final CredentialProcedureService credentialProcedureService;
    private final IssuerFactory issuerFactory;

    public Mono<CredentialProcedureCreationRequest> mapAndBuildLabelCredential(JsonNode credential, String operationMode, String email) {
        LabelCredential labelCredential = objectMapper.convertValue(credential, LabelCredential.class);

        return buildVerifiableCertification(labelCredential)
                .flatMap(verifiableCertificationDecoded ->
                        convertVerifiableCertificationInToString(verifiableCertificationDecoded)
                                .flatMap(decodedCredential ->
                                        buildCredentialProcedureCreationRequest(decodedCredential, verifiableCertificationDecoded, operationMode, email)
                                )
                );
    }

    private Mono<LabelCredential> buildVerifiableCertification(LabelCredential credential) {

        // Build the VerifiableCertification object
        return Mono.just(LabelCredential.builder()
                .context(LABEL_CREDENTIAL_CONTEXT)
                .id(UUID.randomUUID().toString())
                .type(LABEL_CREDENTIAL_TYPES)
                .credentialSubject(credential.credentialSubject())
                .validFrom(credential.validFrom())
                .validUntil(credential.validUntil())
                .build());
    }

    public Mono<String> mapIssuer(String procedureId, SimpleIssuer issuer) {
        return credentialProcedureService.getDecodedCredentialByProcedureId(procedureId)
                .flatMap(credential -> {
                    try {
                        LabelCredential labelCredential = mapStringToVerifiableCertification(credential);
                        return bindIssuer(labelCredential, issuer)
                                .flatMap(this::convertVerifiableCertificationInToString);
                    } catch (InvalidCredentialFormatException e) {
                        return Mono.error(e);
                    }
                });
    }

    public Mono<String> mapCredentialAndBindIssuerInToTheCredential(
            String decodedCredentialString,
            String procedureId) {
        LabelCredential labelCredential = mapStringToVerifiableCertification(decodedCredentialString);

        return issuerFactory.createSimpleIssuer(procedureId, CredentialType.LABEL_CREDENTIAL.getTypeId())
                .flatMap(issuer -> bindIssuer(labelCredential, issuer))
                .flatMap(this::convertVerifiableCertificationInToString);
    }


    public Mono<LabelCredential> bindIssuer(LabelCredential labelCredential, SimpleIssuer issuer) {
        SimpleIssuer issuerCred = SimpleIssuer.builder()
                .id(issuer.id())
                .build();

        return Mono.just(LabelCredential.builder()
                .context(labelCredential.context())
                .id(labelCredential.id())
                .type(labelCredential.type())
                .issuer(issuerCred)
                .credentialSubject(labelCredential.credentialSubject())
                .validFrom(labelCredential.validFrom())
                .validUntil(labelCredential.validUntil())
                .build());
    }

    public Mono<LabelCredentialJwtPayload> buildVerifiableCertificationJwtPayload(LabelCredential credential) {
        return Mono.just(
                LabelCredentialJwtPayload.builder()
                        .JwtId(UUID.randomUUID().toString())
                        .credential(credential)
                        .expirationTime(parseDateToUnixTime(credential.validUntil()))
                        .issuedAt(parseDateToUnixTime(credential.validFrom()))
                        .notValidBefore(parseDateToUnixTime(credential.validFrom()))
                        .issuer(credential.issuer().getId())
                        .subject(credential.credentialSubject().id())
                        .build()
        );
    }

    private long parseDateToUnixTime(String date) {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME);
        return zonedDateTime.toInstant().getEpochSecond();
    }

    public LabelCredential mapStringToVerifiableCertification(String learCredential)
            throws InvalidCredentialFormatException {
        try {
            log.info(objectMapper.readValue(learCredential, LabelCredential.class).toString());
            return objectMapper.readValue(learCredential, LabelCredential.class);
        } catch (JsonProcessingException e) {
            log.error("Error parsing VerifiableCertification", e);
            throw new InvalidCredentialFormatException("Error parsing VerifiableCertification");
        }
    }

    private Mono<String> convertVerifiableCertificationInToString(LabelCredential labelCredential) {
        try {

            return Mono.just(objectMapper.writeValueAsString(labelCredential));
        } catch (JsonProcessingException e) {
            throw new ParseErrorException(e.getMessage());
        }
    }

    public Mono<String> convertVerifiableCertificationJwtPayloadInToString(LabelCredentialJwtPayload labelCredentialJwtPayload) {
        try {
            return Mono.just(objectMapper.writeValueAsString(labelCredentialJwtPayload));
        } catch (JsonProcessingException e) {
            throw new ParseErrorException(e.getMessage());
        }
    }


    private Mono<CredentialProcedureCreationRequest> buildCredentialProcedureCreationRequest(String decodedCredential, LabelCredential labelCredentialDecoded, String operationMode, String email) {
        String organizationId = defaultSignerConfig.getOrganizationIdentifier();
        return Mono.just(CredentialProcedureCreationRequest.builder()
                .credentialId(labelCredentialDecoded.id())
                .organizationIdentifier(organizationId)
                .credentialDecoded(decodedCredential)
                .credentialType(CredentialType.LABEL_CREDENTIAL)
                .subject(labelCredentialDecoded.credentialSubject().id())
                .validUntil(parseEpochSecondIntoTimestamp(parseDateToUnixTime(labelCredentialDecoded.validUntil())))
                .operationMode(operationMode)
                .ownerEmail(email)
                .build()
        );
    }

    private Timestamp parseEpochSecondIntoTimestamp(Long unixEpochSeconds) {
        return Timestamp.from(Instant.ofEpochSecond(unixEpochSeconds));
    }
}
