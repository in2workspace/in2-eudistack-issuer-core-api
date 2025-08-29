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
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
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
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE_DESCRIPTION;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Component
@RequiredArgsConstructor
public class LEARCredentialEmployeeFactory {

    private final ObjectMapper objectMapper;
    private final AccessTokenService accessTokenService;
    private final IssuerFactory issuerFactory;
    private final AppConfig appConfig;

    public Mono<String> bindCryptographicCredentialSubjectId(String decodedCredentialString, String mandateeId){
        LEARCredentialEmployee decodedCredential = mapStringToLEARCredentialEmployee(decodedCredentialString);
        return bindMandateeIdToLearCredentialEmployee(decodedCredential, mandateeId)
                .flatMap(this::convertLEARCredentialEmployeeInToString);
    }

    public Mono<String> mapCredentialAndBindIssuerInToTheCredential(String decodedCredentialString, String procedureId) {
        LEARCredentialEmployee decodedCredential = mapStringToLEARCredentialEmployee(decodedCredentialString);
        return bindIssuerToLearCredentialEmployee(decodedCredential, procedureId)
                .flatMap(this::convertLEARCredentialEmployeeInToString);
    }

    public Mono<CredentialProcedureCreationRequest> mapAndBuildLEARCredentialEmployee(JsonNode learCredential, String operationMode, String email) {
        LEARCredentialEmployee.CredentialSubject baseCredentialSubject = mapJsonNodeToCredentialSubject(learCredential);
        return buildFinalLearCredentialEmployee(baseCredentialSubject)
                .flatMap(credentialDecoded ->
                        convertLEARCredentialEmployeeInToString(credentialDecoded)
                                .flatMap(credentialDecodedString ->
                                        buildCredentialProcedureCreationRequest(credentialDecodedString, credentialDecoded, operationMode, email)
                                )
                );
    }

    //TODO Fix if else cuando se tenga la estructura final de los credenciales en el marketplace
    public LEARCredentialEmployee mapStringToLEARCredentialEmployee(String learCredential) {
        try {
            LEARCredentialEmployee employee;
            if (learCredential.contains("https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1")) {
                employee = objectMapper.readValue(learCredential, LEARCredentialEmployee.class);
            } else if (learCredential.contains("https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2")) {
                JsonNode learCredentialEmployee = objectMapper.readTree(learCredential);
                learCredentialEmployee.get("credentialSubject").get("mandate").get("power").forEach(power -> {
                    ((ObjectNode) power).remove("tmf_function");
                    ((ObjectNode) power).remove("tmf_type");
                    ((ObjectNode) power).remove("tmf_domain");
                    ((ObjectNode) power).remove("tmf_action");
                });
                employee = objectMapper.readValue(learCredentialEmployee.toString(), LEARCredentialEmployee.class);
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

    private Mono<LEARCredentialEmployee> buildFinalLearCredentialEmployee(LEARCredentialEmployee.CredentialSubject baseCredentialSubject) {
        Instant currentTime = Instant.now();
        String validFrom = currentTime.toString();
        String validUntil = currentTime.plus(365, ChronoUnit.DAYS).toString();

        List<Power> populatedPowers = createPopulatedPowers(baseCredentialSubject);
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee = createMandatee(baseCredentialSubject);
        LEARCredentialEmployee.CredentialSubject.Mandate mandate = createMandate(baseCredentialSubject, mandatee, populatedPowers);
        LEARCredentialEmployee.CredentialSubject credentialSubject = createCredentialSubject(mandate);

        String credentialId = UUID.randomUUID().toString();

        return buildCredentialStatus()
                .map(credentialStatus -> LEARCredentialEmployee.builder()
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

    private Mono<CredentialStatus> buildCredentialStatus() {
        String statusListCredential = appConfig.getIssuerBackendUrl() + "/backoffice/v1/credentials/status/1";
        return generateCustomNonce()
                .map(nonce -> CredentialStatus.builder()
                        .id(statusListCredential + "#" + nonce)
                        .type("PlainListEntity")
                        .statusPurpose("revocation")
                        .statusListIndex(nonce)
                        .statusListCredential(statusListCredential)
                        .build());
    }

    private List<Power> createPopulatedPowers(
            LEARCredentialEmployee.CredentialSubject baseCredentialSubject) {
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

    private LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee createMandatee(
            LEARCredentialEmployee.CredentialSubject baseCredentialSubject) {
        return LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                .firstName(baseCredentialSubject.mandate().mandatee().firstName())
                .lastName(baseCredentialSubject.mandate().mandatee().lastName())
                .email(baseCredentialSubject.mandate().mandatee().email())
                .nationality(baseCredentialSubject.mandate().mandatee().nationality())
                .build();
    }

    private LEARCredentialEmployee.CredentialSubject.Mandate createMandate(
            LEARCredentialEmployee.CredentialSubject baseCredentialSubject,
            LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee,
            List<Power> populatedPowers) {
        return LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .id(UUID.randomUUID().toString())
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
        log.debug("buildLEARCredentialEmployeeJwtPayload: {}", learCredentialEmployee);
        return Mono.just(
                LEARCredentialEmployeeJwtPayload.builder()
                        .JwtId(UUID.randomUUID().toString())
                        .learCredentialEmployee(learCredentialEmployee)
                        .expirationTime(parseDateToUnixTime(learCredentialEmployee.validUntil()))
                        .issuedAt(parseDateToUnixTime(learCredentialEmployee.validFrom()))
                        .notValidBefore(parseDateToUnixTime(learCredentialEmployee.validFrom()))
                        .issuer(learCredentialEmployee.issuer().getId())
                        .subject(learCredentialEmployee.credentialSubject().mandate().mandatee().id())
                        .build()
        );
    }

    private long parseDateToUnixTime(String date) {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME);
        return zonedDateTime.toInstant().getEpochSecond();
    }

    private Mono<LEARCredentialEmployee> bindMandateeIdToLearCredentialEmployee(LEARCredentialEmployee decodedCredential, String mandateeId) {
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee baseMandatee =
                decodedCredential.credentialSubject().mandate().mandatee();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee updatedMandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id(mandateeId)
                        .email(baseMandatee.email())
                        .firstName(baseMandatee.firstName())
                        .lastName(baseMandatee.lastName())
                        .nationality(baseMandatee.nationality())
                        .build();

        return Mono.just(LEARCredentialEmployee.builder()
                .context(decodedCredential.context())
                .id(decodedCredential.id())
                .type(decodedCredential.type())
                .description(decodedCredential.description())
                .issuer(decodedCredential.issuer())
                .validFrom(decodedCredential.validFrom())
                .validUntil(decodedCredential.validUntil())
                .credentialSubject(
                        LEARCredentialEmployee.CredentialSubject.builder()
                                .mandate(
                                        LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                                                .id(decodedCredential.credentialSubject().mandate().id())
                                                .mandator(decodedCredential.credentialSubject().mandate().mandator())
                                                .mandatee(updatedMandatee)
                                                .power(decodedCredential.credentialSubject().mandate().power())
                                                .build()
                                )
                                .build()
                )
                .credentialStatus(decodedCredential.credentialStatus())
                .build()
        );
    }

    private Mono<LEARCredentialEmployee> bindIssuerToLearCredentialEmployee(LEARCredentialEmployee decodedCredential, String procedureId) {
        log.debug("🔐: bindIssuerToLearCredentialEmployee");
        return issuerFactory.createDetailedIssuer(procedureId, LEAR_CREDENTIAL_EMPLOYEE)
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

    private Mono<CredentialProcedureCreationRequest> buildCredentialProcedureCreationRequest(String decodedCredential, LEARCredentialEmployee credentialDecoded, String operationMode, String email) {
        return accessTokenService.getOrganizationIdFromCurrentSession()
                .flatMap(organizationId ->
                        Mono.just(
                                CredentialProcedureCreationRequest.builder()
                                        .credentialId(credentialDecoded.id())
                                        .organizationIdentifier(organizationId)
                                        .credentialDecoded(decodedCredential)
                                        .credentialType(CredentialType.LEAR_CREDENTIAL_EMPLOYEE)
                                        .subject(credentialDecoded.credentialSubject().mandate().mandatee().firstName() +
                                                " " +
                                                credentialDecoded.credentialSubject().mandate().mandatee().lastName())
                                        .validUntil(parseEpochSecondIntoTimestamp(parseDateToUnixTime(credentialDecoded.validUntil())))
                                        .operationMode(operationMode)
                                        .ownerEmail(email)
                                        .build()
                        )
                );
    }

    private Timestamp parseEpochSecondIntoTimestamp(Long unixEpochSeconds) {
        return Timestamp.from(Instant.ofEpochSecond(unixEpochSeconds));
    }
}