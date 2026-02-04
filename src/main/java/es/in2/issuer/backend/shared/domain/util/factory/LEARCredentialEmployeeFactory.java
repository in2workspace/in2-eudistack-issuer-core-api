package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.CredentialSerializationException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialEmployeeJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
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
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE_DESCRIPTION;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class LEARCredentialEmployeeFactory {

    private final ObjectMapper objectMapper;
    private final IssuerFactory issuerFactory;

    public Mono<String> bindCryptographicCredentialSubjectId(String decodedCredentialString, String subjectDid) {
        log.info("[BIND] called bindCryptographicCredentialSubjectId subjectDid={}", subjectDid);

        if (subjectDid == null || subjectDid.isBlank()) {
            log.error("[BIND] subjectDid is null/blank -> will NOT be able to bind credentialSubject.id");
        }

        LEARCredentialEmployee decodedCredential = mapStringToLEARCredentialEmployee(decodedCredentialString);

        log.info("[BIND] BEFORE: credentialSubject.id={}, mandatee.id={}",
                decodedCredential.credentialSubject() != null ? decodedCredential.credentialSubject().id() : null,
                decodedCredential.credentialSubject() != null ? decodedCredential.credentialSubject().mandate().mandatee().id() : null
        );

        return bindSubjectIdToLearCredentialEmployee(decodedCredential, subjectDid)
                .doOnNext(updated -> log.info("[BIND] AFTER: credentialSubject.id={}",
                        updated.credentialSubject() != null ? updated.credentialSubject().id() : null
                ))
                .flatMap(this::convertLEARCredentialEmployeeInToString)
                .doOnNext(json -> log.debug("[BIND] JSON contains \"credentialSubject\".id? {}", json.contains("\"credentialSubject\":{\"id\"")));
    }


    public Mono<String> mapCredentialAndBindIssuerInToTheCredential(String decodedCredentialString, String procedureId, String email) {
        LEARCredentialEmployee decodedCredential = mapStringToLEARCredentialEmployee(decodedCredentialString);
        return bindIssuerToLearCredentialEmployee(decodedCredential, procedureId, email)
                .flatMap(this::convertLEARCredentialEmployeeInToString);
    }

    public Mono<CredentialProcedureCreationRequest> mapAndBuildLEARCredentialEmployee(String procedureId, JsonNode learCredential, CredentialStatus credentialStatus, String operationMode, String email) {
        LEARCredentialEmployee.CredentialSubject baseCredentialSubject = mapJsonNodeToCredentialSubject(learCredential);
        return buildFinalLearCredentialEmployee(baseCredentialSubject, credentialStatus)
                .flatMap(credentialDecoded ->
                        convertLEARCredentialEmployeeInToString(credentialDecoded)
                                .flatMap(credentialDecodedString ->
                                        buildCredentialProcedureCreationRequest(procedureId, credentialDecodedString, credentialDecoded, operationMode, email)
                                )
                );
    }

    //TODO Fix if else cuando se tenga la estructura final de los credenciales en el marketplace
    public LEARCredentialEmployee mapStringToLEARCredentialEmployee(String learCredential) {
        try {
            LEARCredentialEmployee employee;
            if (learCredential.contains("https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1")) {
                employee = objectMapper.readValue(learCredential, LEARCredentialEmployee.class);
            } else if (
                    learCredential.contains("https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2")
            ) {
                JsonNode learCredentialEmployee = objectMapper.readTree(learCredential);
                learCredentialEmployee.get("credentialSubject").get("mandate").get("power").forEach(power -> {
                    ((ObjectNode) power).remove("tmf_function");
                    ((ObjectNode) power).remove("tmf_type");
                    ((ObjectNode) power).remove("tmf_domain");
                    ((ObjectNode) power).remove("tmf_action");
                });
                employee = objectMapper.readValue(learCredentialEmployee.toString(), LEARCredentialEmployee.class);
            } else if(learCredential.contains(CREDENTIALS_EUDISTACK_LEAR_CREDENTIAL_EMPLOYEE_CONTEXT)){
                                employee = objectMapper.readValue(learCredential, LEARCredentialEmployee.class);
            } else {
                throw new InvalidCredentialFormatException("Invalid credential format");
            }
            log.info("✅ {}", employee.toString());
            return employee;
        } catch (JsonProcessingException e) {
            log.error("Error parsing LEARCredentialEmployee", e);
            throw new InvalidCredentialFormatException("Error parsing LEARCredentialEmployee");
        }
    }

    private LEARCredentialEmployee.CredentialSubject mapJsonNodeToCredentialSubject(JsonNode jsonNode) {
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(jsonNode, LEARCredentialEmployee.CredentialSubject.Mandate.class);
        return LEARCredentialEmployee.CredentialSubject.builder()
                .mandate(mandate)
                .build();
    }

    private Mono<LEARCredentialEmployee> buildFinalLearCredentialEmployee(LEARCredentialEmployee.CredentialSubject baseCredentialSubject, CredentialStatus credentialStatus) {
        Instant currentTime = Instant.now();
        String validFrom = currentTime.toString();
        String validUntil = currentTime.plus(365, ChronoUnit.DAYS).toString();

        List<Power> populatedPowers = createPopulatedPowers(baseCredentialSubject);
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee = createMandatee(baseCredentialSubject);
        LEARCredentialEmployee.CredentialSubject.Mandate mandate = createMandate(baseCredentialSubject, mandatee, populatedPowers);
        LEARCredentialEmployee.CredentialSubject credentialSubject = createCredentialSubject(mandate);

        String credentialId = "urn:uuid:" + UUID.randomUUID();

        return Mono.just(LEARCredentialEmployee.builder()
                        .context(LEAR_CREDENTIAL_EMPLOYEE_CONTEXT)
                        .id(credentialId)
                        .type(List.of(LEAR_CREDENTIAL_EMPLOYEE, VERIFIABLE_CREDENTIAL))
                        .description(LEAR_CREDENTIAL_EMPLOYEE_DESCRIPTION)
                        .credentialSubject(credentialSubject)
                        .validFrom(validFrom)
                        .validUntil(validUntil)
                        .credentialStatus(credentialStatus)
                        .build());
    }

    private List<Power> createPopulatedPowers(
            LEARCredentialEmployee.CredentialSubject baseCredentialSubject) {
        return baseCredentialSubject.mandate().power().stream()
                .map(power -> Power.builder()
                        .type(power.type())
                        .domain(power.domain())
                        .function(power.function())
                        .action(power.action())
                        .build())
                .toList();
    }

    private LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee createMandatee(
            LEARCredentialEmployee.CredentialSubject baseCredentialSubject) {
        return LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                .firstName(baseCredentialSubject.mandate().mandatee().firstName())
                .employeeId(baseCredentialSubject.mandate().mandatee().employeeId())
                .lastName(baseCredentialSubject.mandate().mandatee().lastName())
                .email(baseCredentialSubject.mandate().mandatee().email())
                .build();
    }

    private LEARCredentialEmployee.CredentialSubject.Mandate createMandate(
            LEARCredentialEmployee.CredentialSubject baseCredentialSubject,
            LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee,
            List<Power> populatedPowers) {
        return LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(baseCredentialSubject.mandate().mandator())
                .mandatee(mandatee)
                .power(populatedPowers)
                .build();
    }

    private LEARCredentialEmployee.CredentialSubject createCredentialSubject(
            LEARCredentialEmployee.CredentialSubject.Mandate mandate) {
        return LEARCredentialEmployee.CredentialSubject.builder()
                .mandate(mandate)
                .build();
    }

    public Mono<LEARCredentialEmployeeJwtPayload> buildLEARCredentialEmployeeJwtPayload(LEARCredentialEmployee learCredentialEmployee) {
        return Mono.fromCallable(() -> {
            String subjectDid = learCredentialEmployee.credentialSubject().id();
            if (subjectDid == null || subjectDid.isBlank()) {
                throw new IllegalStateException("Missing credentialSubject.id (cryptographic binding DID)");
            }

            Map<String, Object> cnf = Map.of("kid", subjectDid);

            return LEARCredentialEmployeeJwtPayload.builder()
                    .JwtId(UUID.randomUUID().toString())
                    .learCredentialEmployee(learCredentialEmployee)
                    .expirationTime(parseDateToUnixTime(learCredentialEmployee.validUntil()))
                    .issuedAt(parseDateToUnixTime(learCredentialEmployee.validFrom()))
                    .notValidBefore(parseDateToUnixTime(learCredentialEmployee.validFrom()))
                    .issuer(learCredentialEmployee.issuer().getId())
                    .subject(subjectDid)
                    .cnf(cnf)
                    .build();
        });
    }


    private long parseDateToUnixTime(String date) {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME);
        return zonedDateTime.toInstant().getEpochSecond();
    }

    private Mono<LEARCredentialEmployee> bindSubjectIdToLearCredentialEmployee(
            LEARCredentialEmployee decodedCredential,
            String subjectDid
    ) {
        var currentSubject = decodedCredential.credentialSubject();

        var updatedSubject = LEARCredentialEmployee.CredentialSubject.builder()
                .id(subjectDid)
                .mandate(currentSubject.mandate())
                .build();

        return Mono.just(
                LEARCredentialEmployee.builder()
                        .context(decodedCredential.context())
                        .id(decodedCredential.id())
                        .type(decodedCredential.type())
                        .description(decodedCredential.description())
                        .issuer(decodedCredential.issuer())
                        .validFrom(decodedCredential.validFrom())
                        .validUntil(decodedCredential.validUntil())
                        .credentialSubject(updatedSubject)
                        .credentialStatus(decodedCredential.credentialStatus())
                        .build()
        );
    }


    private Mono<LEARCredentialEmployee> bindIssuerToLearCredentialEmployee(LEARCredentialEmployee decodedCredential, String procedureId, String email) {
        log.debug("🔐: bindIssuerToLearCredentialEmployee");
        return issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, email)
                .map(issuer -> LEARCredentialEmployee.builder()
                        .context(decodedCredential.context())
                        .id(decodedCredential.id())
                        .type(decodedCredential.type())
                        .description(decodedCredential.description())
                        .issuer(issuer)
                        .validFrom(decodedCredential.validFrom())
                        .validUntil(decodedCredential.validUntil())
                        .credentialSubject(decodedCredential.credentialSubject())
                        .credentialStatus(decodedCredential.credentialStatus())
                        .build());
    }

    private Mono<String> convertLEARCredentialEmployeeInToString(LEARCredentialEmployee credentialDecoded) {
        try {
            return Mono.just(objectMapper.writeValueAsString(credentialDecoded));
        } catch (JsonProcessingException e) {
            return Mono.error(new CredentialSerializationException("Error serializing LEARCredentialEmployee to string."));
        }
    }

    public Mono<String> convertLEARCredentialEmployeeJwtPayloadInToString(LEARCredentialEmployeeJwtPayload credential) {
        try {
            return Mono.just(objectMapper.writeValueAsString(credential));
        } catch (JsonProcessingException e) {
            return Mono.error(new CredentialSerializationException("Error serializing LEARCredentialEmployee JWT payload to string."));
        }
    }

    private Mono<CredentialProcedureCreationRequest> buildCredentialProcedureCreationRequest(String procedureId, String decodedCredential, LEARCredentialEmployee credentialDecoded, String operationMode, String email) {
        String mandatorOrgId = credentialDecoded.credentialSubject().mandate().mandator().organizationIdentifier();

        return Mono.just(
            CredentialProcedureCreationRequest.builder()
                    .procedureId(procedureId)
                    .organizationIdentifier(mandatorOrgId)
                    .credentialDecoded(decodedCredential)
                    .credentialType(CredentialType.LEAR_CREDENTIAL_EMPLOYEE)
                    .subject(credentialDecoded.credentialSubject().mandate().mandatee().firstName() +
                            " " +
                            credentialDecoded.credentialSubject().mandate().mandatee().lastName())
                    .validUntil(parseEpochSecondIntoTimestamp(parseDateToUnixTime(credentialDecoded.validUntil())))
                    .operationMode(operationMode)
                    .email(email)
                    .build()
            );
    }

    private Timestamp parseEpochSecondIntoTimestamp(Long unixEpochSeconds) {
        return Timestamp.from(Instant.ofEpochSecond(unixEpochSeconds));
    }
}