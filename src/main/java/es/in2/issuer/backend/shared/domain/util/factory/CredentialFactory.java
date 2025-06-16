package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedDataCredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Component
@RequiredArgsConstructor
@Slf4j
public class CredentialFactory {

    public final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    public final LEARCredentialMachineFactory learCredentialMachineFactory;
    public final VerifiableCertificationFactory verifiableCertificationFactory;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final ObjectMapper objectMapper;

    private static final Map<String, String> SUBJECT_BINDING_PATH = Map.of(
            LEAR_CREDENTIAL_EMPLOYEE, "credentialSubject.mandate.mandatee.id",
            LEAR_CREDENTIAL_MACHINE, "credentialSubject.mandate.mandatee.id"
    );

    public Mono<CredentialProcedureCreationRequest> mapCredentialIntoACredentialProcedureRequest(String processId, PreSubmittedDataCredentialRequest preSubmittedDataCredentialRequest, String token) {
        JsonNode credential = preSubmittedDataCredentialRequest.payload();
        String operationMode = preSubmittedDataCredentialRequest.operationMode();
        if (preSubmittedDataCredentialRequest.schema().equals(LEAR_CREDENTIAL_EMPLOYEE)) {
            return learCredentialEmployeeFactory.mapAndBuildLEARCredentialEmployee(credential, operationMode)
                    .doOnSuccess(learCredentialEmployee -> log.info("ProcessID: {} - LEARCredentialEmployee mapped: {}", processId, credential));
        } else if (preSubmittedDataCredentialRequest.schema().equals(VERIFIABLE_CERTIFICATION)) {
            return verifiableCertificationFactory.mapAndBuildVerifiableCertification(credential, token, operationMode)
                    .doOnSuccess(verifiableCertification -> log.info("ProcessID: {} - VerifiableCertification mapped: {}", processId, credential));
        }
        return Mono.error(new CredentialTypeUnsupportedException(preSubmittedDataCredentialRequest.schema()));
    }

    public Mono<String> mapCredentialAndBindMandateeId(String processId, String credentialType, String decodedCredential, String mandateeId) {
        if (credentialType.equals(LEAR_CREDENTIAL_EMPLOYEE)) {
            return learCredentialEmployeeFactory.mapCredentialAndBindMandateeIdInToTheCredential(decodedCredential, mandateeId)
                    .doOnSuccess(learCredentialEmployee -> log.info("ProcessID: {} - Credential mapped and bind to the id: {}", processId, learCredentialEmployee));
        }
        return Mono.error(new CredentialTypeUnsupportedException(credentialType));
    }

    public Mono<Void> mapCredentialBindIssuerAndUpdateDB(String processId, String procedureId, String decodedCredential, String credentialType, String format, String authServerNonce) {
        if (credentialType.equals(LEAR_CREDENTIAL_EMPLOYEE)) {
            return learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId)
                    .flatMap(bindCredential -> {
                        log.info("ProcessID: {} - Credential mapped and bind to the issuer: {}", processId, bindCredential);
                        return credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindCredential, format)
                                .then(deferredCredentialMetadataService.updateDeferredCredentialByAuthServerNonce(authServerNonce, format));
                    });
        }
        return Mono.error(new CredentialTypeUnsupportedException(credentialType));
    }

    public Mono<String> credentialSubjectBinder(String credentialData, String credentialType, String did) {
        final String errorMsg = "Error parsing credential";

        try {
            JsonNode rootNode = objectMapper.readTree(credentialData);
            String idPath = SUBJECT_BINDING_PATH.get(credentialType);
            if (idPath == null || idPath.isEmpty()) {
                return Mono.error(new ParseErrorException(errorMsg));
            }

            String[] keys = idPath.split("\\.");
            JsonNode currentNode = rootNode;

            for (int i = 0; i < keys.length - 1; i++) {
                currentNode = currentNode.path(keys[i]);
                if (currentNode.isMissingNode()) {
                    return Mono.error(new ParseErrorException(errorMsg));
                }
            }

            if (!(currentNode instanceof ObjectNode objectNode)) {
                return Mono.error(new ParseErrorException(errorMsg));
            }

            String lastKey = keys[keys.length - 1];
            objectNode.put(lastKey, did);

            String updatedJson = objectMapper.writeValueAsString(rootNode);
            return Mono.just(updatedJson);

        } catch (JsonProcessingException e) {
            return Mono.error(new ParseErrorException(errorMsg));
        }
    }

    public Mono<String> setIssuer(String credentialData, DetailedIssuer issuer) {
        final String errorMsg = "Error setting issuer in credential";

        try {
            JsonNode rootNode = objectMapper.readTree(credentialData);

            if (!(rootNode instanceof ObjectNode objectNode)) {
                return Mono.error(new ParseErrorException(errorMsg));
            }

            JsonNode issuerNode = objectMapper.valueToTree(issuer);
            objectNode.set("issuer", issuerNode);

            String updatedJson = objectMapper.writeValueAsString(objectNode);
            return Mono.just(updatedJson);

        } catch (JsonProcessingException e) {
            return Mono.error(new ParseErrorException(errorMsg));
        }
    }

    public Mono<String> setCredentialStatus(String credentialData) {
        final String errorMsg = "Error setting issuer in credential";

        try {
            ObjectNode credential = (ObjectNode) objectMapper.readTree(credentialData);

            ObjectNode credentialStatus = objectMapper.createObjectNode();
            String uuid = credential.get("id").asText();

            // TODO: Generate nonce to ensure credential privacy. The nonce will be saved in DDBB.

            credentialStatus.put("id", "https://issuer.dome-marketplace.eu/credentials/status/1#" + uuid);
            credentialStatus.put("type", "PlainListEntity");
            credentialStatus.put("statusPurpose", "revocation");
            credentialStatus.put("statusListIndex", uuid);
            credentialStatus.put("statusListCredential", "https://issuer.dome-marketplace.eu/credentials/status/1");

            credential.set("credentialStatus", credentialStatus);

            String updatedJson = objectMapper.writeValueAsString(credential);
            return Mono.just(updatedJson);

        } catch (JsonProcessingException e) {
            return Mono.error(new ParseErrorException(errorMsg));
        }
    }
}
