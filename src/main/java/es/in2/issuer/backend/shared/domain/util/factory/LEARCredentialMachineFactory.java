package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class LEARCredentialMachineFactory {

    private final ObjectMapper objectMapper;
    private final AccessTokenService accessTokenService;
    private final CorsProperties corsProperties;
    private final IssuerFactory issuerFactory;

    public LEARCredentialMachine mapStringToLEARCredentialMachine(String learCredential)
            throws InvalidCredentialFormatException {
        try {
            log.debug(objectMapper.readValue(learCredential, LEARCredentialMachine.class).toString());
            return objectMapper.readValue(learCredential, LEARCredentialMachine.class);
        } catch (JsonProcessingException e) {
            log.error("Error parsing LEARCredentialMachine", e);
            throw new InvalidCredentialFormatException("Error parsing LEARCredentialMachine");
        }
    }

    public Mono<CredentialProcedureCreationRequest> mapAndBuildLEARCredentialMachine(JsonNode learCredential, String operationMode, String email) {
        LEARCredentialMachine.CredentialSubject baseCredentialSubject = mapJsonNodeToCredentialSubject(learCredential);
        return buildFinalLearCredentialMachine(baseCredentialSubject)
                .flatMap(credentialDecoded ->
                        convertLEARCredentialMachineInToString(credentialDecoded)
                                .flatMap(credentialDecodedString ->
                                        buildCredentialProcedureCreationRequest(credentialDecodedString, credentialDecoded, operationMode, email)
                                )
                );
    }

    private LEARCredentialMachine.CredentialSubject mapJsonNodeToCredentialSubject(JsonNode jsonNode) {
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(jsonNode, LEARCredentialMachine.CredentialSubject.Mandate.class);
        return LEARCredentialMachine.CredentialSubject.builder()
                .mandate(mandate)
                .build();
    }

    private Mono<LEARCredentialMachine> buildFinalLearCredentialMachine(LEARCredentialMachine.CredentialSubject baseCredentialSubject) {
        Instant currentTime = Instant.now();
        String validFrom = currentTime.toString();
        String validUntil = currentTime.plus(365, ChronoUnit.DAYS).toString();

        String credentialId = UUID.randomUUID().toString();
        LEARCredentialMachine learCredentialMachine = LEARCredentialMachine.builder()
                .context(CREDENTIAL_CONTEXT_LEAR_CREDENTIAL_MACHINE)
                .id(credentialId)
                .type(List.of(LEAR_CREDENTIAL_MACHINE, VERIFIABLE_CREDENTIAL))
                .credentialSubject(baseCredentialSubject)
                .validFrom(validFrom)
                .validUntil(validUntil)
                .credentialStatus(buildCredentialStatus(credentialId))
                .build();

        return Mono.just(learCredentialMachine);
    }

    private CredentialStatus buildCredentialStatus(String credentialId) {
        String statusListCredential = corsProperties.defaultAllowedOrigins().stream().findFirst() + "/credentials/status/1";
        return CredentialStatus.builder()
                .id(statusListCredential + "#" + credentialId)
                .type("PlainListEntity")
                .statusPurpose("revocation")
                .statusListIndex(credentialId)
                .statusListCredential(statusListCredential)
                .build();
    }

    private Mono<String> convertLEARCredentialMachineInToString(LEARCredentialMachine credentialDecoded) {
        try {
            return Mono.just(objectMapper.writeValueAsString(credentialDecoded));
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException());
        }
    }

    private Mono<CredentialProcedureCreationRequest> buildCredentialProcedureCreationRequest(String decodedCredential, LEARCredentialMachine credentialDecoded, String operationMode, String email) {
        return accessTokenService.getOrganizationIdFromCurrentSession()
                .flatMap(organizationId ->
                        Mono.just(
                                CredentialProcedureCreationRequest.builder()
                                        .credentialId(credentialDecoded.id())
                                        .organizationIdentifier(organizationId)
                                        .credentialDecoded(decodedCredential)
                                        .credentialType(CredentialType.LEAR_CREDENTIAL_MACHINE)
                                        .subject(credentialDecoded.credentialSubject().mandate().mandatee().domain())
                                        .validUntil(parseEpochSecondIntoTimestamp(parseDateToUnixTime(credentialDecoded.validUntil())))
                                        .operationMode(operationMode)
                                        .ownerEmail(email)
                                        .build()
                        )
                );
    }

    private long parseDateToUnixTime(String date) {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME);
        return zonedDateTime.toInstant().getEpochSecond();
    }

    private Timestamp parseEpochSecondIntoTimestamp(Long unixEpochSeconds) {
        return Timestamp.from(Instant.ofEpochSecond(unixEpochSeconds));
    }

    public Mono<String> mapCredentialAndBindIssuerInToTheCredential(
            String decodedCredentialString,
            String procedureId) {
        LEARCredentialMachine learCredentialMachine = mapStringToLEARCredentialMachine(decodedCredentialString);

        return issuerFactory.createSimpleIssuer(procedureId, LEAR_CREDENTIAL_MACHINE)
                .flatMap(issuer -> bindIssuer(learCredentialMachine, issuer))
                .flatMap(this::convertLEARCredentialMachineInToString);
    }

    public Mono<LEARCredentialMachine> bindIssuer(LEARCredentialMachine learCredentialMachine, SimpleIssuer issuer) {
        SimpleIssuer issuerCred = SimpleIssuer.builder()
                .id(issuer.id())
                .build();

        return Mono.just(LEARCredentialMachine.builder()
                .context(learCredentialMachine.context())
                .id(learCredentialMachine.id())
                .type(learCredentialMachine.type())
                .name(learCredentialMachine.name())
                .description(learCredentialMachine.description())
                .issuer(issuerCred)
                .validFrom(learCredentialMachine.validFrom())
                .validUntil(learCredentialMachine.validUntil())
                .credentialSubject(learCredentialMachine.credentialSubject())
                .credentialStatus(learCredentialMachine.credentialStatus())
                .build());
    }
}
