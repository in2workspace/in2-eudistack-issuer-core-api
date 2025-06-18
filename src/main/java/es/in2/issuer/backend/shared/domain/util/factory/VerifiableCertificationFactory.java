package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.VerifiableCertification;
import es.in2.issuer.backend.shared.domain.model.dto.VerifiableCertificationJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.infrastructure.config.DefaultSignerConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_CONTEXT_LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.VERIFIABLE_CERTIFICATION_TYPE;

@Component
@RequiredArgsConstructor
@Slf4j
public class VerifiableCertificationFactory {
    private final DefaultSignerConfig defaultSignerConfig;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    private final ObjectMapper objectMapper;
    private final JWTService jwtService;
    private final CredentialProcedureService credentialProcedureService;

    public Mono<CredentialProcedureCreationRequest> mapAndBuildVerifiableCertification(JsonNode credential, String idToken, String operationMode) {
        VerifiableCertification verifiableCertification = objectMapper.convertValue(credential, VerifiableCertification.class);
        SignedJWT signedJWT = jwtService.parseJWT(idToken);
        // The claim is called vc_json because we use the id_token from the VCVerifier that return the vc in json string format
        String vcClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), "vc_json");
        String processedVc;

        try {
            processedVc = objectMapper.readValue(vcClaim, String.class);
        } catch (JsonProcessingException e) {
            return Mono.error(new ParseErrorException("Error parsing id_token credential: " + e));
        }
        LEARCredentialEmployee learCredentialEmployee = learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(processedVc);

        return buildVerifiableCertification(verifiableCertification, learCredentialEmployee)
                .flatMap(verifiableCertificationDecoded ->
                        convertVerifiableCertificationInToString(verifiableCertificationDecoded)
                                .flatMap(decodedCredential ->
                                        buildCredentialProcedureCreationRequest(decodedCredential, verifiableCertificationDecoded, operationMode)
                                )
                );
    }

    private Mono<VerifiableCertification> buildVerifiableCertification(VerifiableCertification credential, LEARCredentialEmployee learCredentialEmployee) {
        // Compliance list with new IDs
        List<VerifiableCertification.CredentialSubject.Compliance> populatedCompliance = credential.credentialSubject().compliance().stream()
                .map(compliance -> VerifiableCertification.CredentialSubject.Compliance.builder()
                        .id(UUID.randomUUID().toString())
                        .hash(compliance.hash())
                        .scope(compliance.scope())
                        .standard(compliance.standard())
                        .build())
                .toList();

        VerifiableCertification.Atester atester = VerifiableCertification.Atester.builder()
                .firstName(learCredentialEmployee.credentialSubject().mandate().mandatee().firstName())
                .lastName(learCredentialEmployee.credentialSubject().mandate().mandatee().lastName())
                .country(learCredentialEmployee.credentialSubject().mandate().mandator().country())
                .id(learCredentialEmployee.credentialSubject().mandate().mandatee().id())
                .organization(learCredentialEmployee.credentialSubject().mandate().mandator().organization())
                .organizationIdentifier(learCredentialEmployee.credentialSubject().mandate().mandator().organizationIdentifier())
                .build();

        // Build the VerifiableCertification object
        return Mono.just(VerifiableCertification.builder()
                .context(CREDENTIAL_CONTEXT_LEAR_CREDENTIAL_EMPLOYEE)
                .id(UUID.randomUUID().toString())
                .type(VERIFIABLE_CERTIFICATION_TYPE)
                .credentialSubject(VerifiableCertification.CredentialSubject.builder()
                        .company(credential.credentialSubject().company())
                        .product(credential.credentialSubject().product())
                        .compliance(populatedCompliance)
                        .build())
                .validFrom(credential.validFrom())
                .validUntil(credential.validUntil())
                .atester(atester)
                .build());
    }

    public Mono<String> mapIssuerAndSigner(String procedureId, DetailedIssuer issuer) {
        return credentialProcedureService.getDecodedCredentialByProcedureId(procedureId)
                .flatMap(credential -> {
                    try {
                        VerifiableCertification verifiableCertification = mapStringToVerifiableCertification(credential);
                        return bindIssuerAndSigner(verifiableCertification, issuer)
                                .flatMap(this::convertVerifiableCertificationInToString);
                    } catch (InvalidCredentialFormatException e) {
                        return Mono.error(e);
                    }
                });
    }

    public Mono<VerifiableCertification> bindIssuerAndSigner(VerifiableCertification verifiableCertification, DetailedIssuer issuer) {
        VerifiableCertification.Signer signer = VerifiableCertification.Signer.builder()
                .commonName(issuer.commonName())
                .country(issuer.country())
                .emailAddress(verifiableCertification.credentialSubject().company().email())
                .organization(issuer.organization())
                .organizationIdentifier(issuer.organizationIdentifier())
                .serialNumber(issuer.serialNumber())
                .build();

        VerifiableCertification.Issuer issuerCred = VerifiableCertification.Issuer.builder()
                .commonName(issuer.commonName())
                .country(issuer.country())
                .id(issuer.id())
                .organization(issuer.organization())
                .build();

        return Mono.just(VerifiableCertification.builder()
                .context(verifiableCertification.context())
                .id(verifiableCertification.id())
                .type(verifiableCertification.type())
                .issuer(issuerCred)
                .credentialSubject(verifiableCertification.credentialSubject())
                .validFrom(verifiableCertification.validFrom())
                .validUntil(verifiableCertification.validUntil())
                .signer(signer)
                .atester(verifiableCertification.atester())
                .build());
    }

    public Mono<VerifiableCertificationJwtPayload> buildVerifiableCertificationJwtPayload(VerifiableCertification credential) {
        return Mono.just(
                VerifiableCertificationJwtPayload.builder()
                        .JwtId(UUID.randomUUID().toString())
                        .credential(credential)
                        .expirationTime(parseDateToUnixTime(credential.validUntil()))
                        .issuedAt(parseDateToUnixTime(credential.validFrom()))
                        .notValidBefore(parseDateToUnixTime(credential.validFrom()))
                        .issuer(credential.issuer().id())
                        .subject(credential.credentialSubject().product().productId())
                        .build()
        );
    }

    private long parseDateToUnixTime(String date) {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME);
        return zonedDateTime.toInstant().getEpochSecond();
    }

    public VerifiableCertification mapStringToVerifiableCertification(String learCredential)
            throws InvalidCredentialFormatException {
        try {
            log.info(objectMapper.readValue(learCredential, VerifiableCertification.class).toString());
            return objectMapper.readValue(learCredential, VerifiableCertification.class);
        } catch (JsonProcessingException e) {
            log.error("Error parsing VerifiableCertification", e);
            throw new InvalidCredentialFormatException("Error parsing VerifiableCertification");
        }
    }

    private Mono<String> convertVerifiableCertificationInToString(VerifiableCertification verifiableCertification) {
        try {

            return Mono.just(objectMapper.writeValueAsString(verifiableCertification));
        } catch (JsonProcessingException e) {
            throw new ParseErrorException(e.getMessage());
        }
    }

    public Mono<String> convertVerifiableCertificationJwtPayloadInToString(VerifiableCertificationJwtPayload verifiableCertificationJwtPayload) {
        try {
            return Mono.just(objectMapper.writeValueAsString(verifiableCertificationJwtPayload));
        } catch (JsonProcessingException e) {
            throw new ParseErrorException(e.getMessage());
        }
    }


    private Mono<CredentialProcedureCreationRequest> buildCredentialProcedureCreationRequest(String decodedCredential, VerifiableCertification verifiableCertificationDecoded, String operationMode) {
        String organizationId = defaultSignerConfig.getOrganizationIdentifier();
        return Mono.just(CredentialProcedureCreationRequest.builder()
                .credentialId(verifiableCertificationDecoded.id())
                .organizationIdentifier(organizationId)
                .credentialDecoded(decodedCredential)
                .credentialType(CredentialType.VERIFIABLE_CERTIFICATION)
                .subject(verifiableCertificationDecoded.credentialSubject().product().productName())
                .validUntil(parseEpochSecondIntoTimestamp(parseDateToUnixTime(verifiableCertificationDecoded.validUntil())))
                .operationMode(operationMode)
                .build()
        );
    }

    private Timestamp parseEpochSecondIntoTimestamp(Long unixEpochSeconds) {
        return Timestamp.from(Instant.ofEpochSecond(unixEpochSeconds));
    }
}
