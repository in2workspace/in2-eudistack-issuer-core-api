package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
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

import static es.in2.issuer.backend.backoffice.domain.util.Constants.LEAR_CREDENTIAL_MACHINE_DESCRIPTION;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class LEARCredentialMachineFactory {
    private final ObjectMapper objectMapper;
    private final AccessTokenService accessTokenService;

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

    public Mono<CredentialProcedureCreationRequest> mapAndBuildLEARCredentialMachine(JsonNode learCredential, String operationMode) {
        LEARCredentialMachine.CredentialSubject baseCredentialSubject = mapJsonNodeToCredentialSubjectForMachine(learCredential);
        return buildFinalLearCredentialMachine(baseCredentialSubject)
                .flatMap(credentialDecoded ->
                        convertLEARCredentialMachineIntoString(credentialDecoded)
                                .flatMap(credentialDecodedString ->
                                        buildCredentialProcedureCreationRequest(credentialDecodedString, credentialDecoded, operationMode)
                                )
                );
    }

    private LEARCredentialMachine.CredentialSubject mapJsonNodeToCredentialSubjectForMachine(JsonNode jsonNode) {
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

        List<Power> populatedPowers = createPopulatedPowers(baseCredentialSubject);
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee = createMandatee(baseCredentialSubject);
        LEARCredentialMachine.CredentialSubject.Mandate mandate = createMandate(baseCredentialSubject, mandatee, populatedPowers);
        LEARCredentialMachine.CredentialSubject credentialSubject = createCredentialSubject(mandate);

        LEARCredentialMachine credentialMachine = LEARCredentialMachine.builder()
                .context(LEAR_CREDENTIAL_MACHINE_CONTEXT)
                .id(UUID.randomUUID().toString())
                .type(List.of(LEAR_CREDENTIAL_MACHINE, VERIFIABLE_CREDENTIAL))
                .description(LEAR_CREDENTIAL_MACHINE_DESCRIPTION)
                .credentialSubject(credentialSubject)
                .validFrom(validFrom)
                .validUntil(validUntil)
                .build();

        return Mono.just(credentialMachine);
    }

    private List<Power> createPopulatedPowers(LEARCredentialMachine.CredentialSubject baseCredentialSubject) {
        return baseCredentialSubject.mandate().power().stream()
                .map(power -> Power.builder()
                        .id(UUID.randomUUID().toString())
                        .type(power.type())
                        .domain(power.domain())
                        .function(power.function())
                        .action(power.action())
                        .build())
                .toList();
    }

    private LEARCredentialMachine.CredentialSubject.Mandate.Mandatee createMandatee(LEARCredentialMachine.CredentialSubject baseCredentialSubject) {
        return LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                .id(baseCredentialSubject.mandate().mandatee().id())
                .domain(baseCredentialSubject.mandate().mandatee().domain())
                .ipAddress(baseCredentialSubject.mandate().mandatee().ipAddress())
                .build();
    }

    private LEARCredentialMachine.CredentialSubject.Mandate createMandate(
            LEARCredentialMachine.CredentialSubject baseCredentialSubject,
            LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee,
            List<Power> populatedPowers) {
        return LEARCredentialMachine.CredentialSubject.Mandate.builder()
                .id(UUID.randomUUID().toString())
                .mandator(baseCredentialSubject.mandate().mandator())
                .mandatee(mandatee)
                .power(populatedPowers)
                .build();
    }

    private LEARCredentialMachine.CredentialSubject createCredentialSubject(
            LEARCredentialMachine.CredentialSubject.Mandate mandate) {
        return LEARCredentialMachine.CredentialSubject.builder()
                .mandate(mandate)
                .build();
    }

    private Mono<String> convertLEARCredentialMachineIntoString(LEARCredentialMachine credentialDecoded) {
        try {
            return Mono.just(objectMapper.writeValueAsString(credentialDecoded));
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException("Error serializing LEARCredentialMachine", e));
        }
    }

    private Mono<CredentialProcedureCreationRequest> buildCredentialProcedureCreationRequest(
            String decodedCredential,
            LEARCredentialMachine credentialDecoded,
            String operationMode) {

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
                                        .build()
                        )
                );
    }

    private Timestamp parseEpochSecondIntoTimestamp(Long unixEpochSeconds) {
        return Timestamp.from(Instant.ofEpochSecond(unixEpochSeconds));
    }

    private long parseDateToUnixTime(String date) {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME);
        return zonedDateTime.toInstant().getEpochSecond();
    }
}
