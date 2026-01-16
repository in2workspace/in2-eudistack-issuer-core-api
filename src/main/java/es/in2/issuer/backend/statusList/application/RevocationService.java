package es.in2.issuer.backend.statusList.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.statusList.application.policies.StatusListPdpService;
import es.in2.issuer.backend.statusList.domain.spi.StatusListProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import es.in2.issuer.backend.credentialStatus.domain.service.LegacyCredentialStatusRevocationService;


import static java.util.Objects.requireNonNull;

@Service
@RequiredArgsConstructor
public class RevocationService {

    private static final String BITSTRING_ENTRY_TYPE = "BitstringStatusListEntry";
    private static final String REVOKED = "REVOKED";

    private final StatusListProvider statusListProvider;

    private final AccessTokenService accessTokenService;
    private final StatusListPdpService statusListPdpService;
    private final CredentialProcedureService credentialProcedureService;
    private final ObjectMapper objectMapper;
    private final EmailService emailService;
    private final LegacyCredentialStatusRevocationService legacyCredentialStatusRevocationService;



    private record Context(String token, CredentialProcedure procedure) { }

    public Mono<Void> revoke(String processId, String bearerToken, String credentialProcedureId, int listId) {
        requireNonNull(processId, "processId cannot be null");
        requireNonNull(bearerToken, "bearerToken cannot be null");
        requireNonNull(credentialProcedureId, "credentialProcedureId cannot be null");

        return accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token ->
                        credentialProcedureService.getCredentialProcedureById(credentialProcedureId)
                                .flatMap(procedure ->
                                        statusListPdpService.validateRevokeCredential(processId, token, procedure)
                                                .thenReturn(new Context(token, procedure))
                                )
                )
                .flatMap(ctx -> {
                    CredentialStatus credentialStatus = parseCredentialStatus(ctx.procedure.getCredentialDecoded());

                    // Assumption: procedureId == procedureId for bitstring mapping
                    return routeRevocation(listId, credentialStatus, ctx.token, credentialProcedureId)
                            .then(credentialProcedureService.updateCredentialProcedureCredentialStatusToRevoke(ctx.procedure))
                            .then(emailService.notifyIfCredentialStatusChanges(ctx.procedure, REVOKED));
                });
    }

    private Mono<Void> routeRevocation(int listId, CredentialStatus credentialStatus, String token, String procedureId) {
        if (BITSTRING_ENTRY_TYPE.equals(credentialStatus.type())) {
            return statusListProvider.revoke(procedureId, token);
        }
        return legacyCredentialStatusRevocationService.revoke(listId, credentialStatus);
    }

    /**
     * Optional helper for internal callers that already have procedureId + token.
     */
    public Mono<Void> revokeByprocedureId(String procedureId, String token) {
        requireNonNull(procedureId, "procedureId cannot be null");
        requireNonNull(token, "token cannot be null");
        return statusListProvider.revoke(procedureId, token);
    }

    //todo look for similar functions to avoid duplication
    private CredentialStatus parseCredentialStatus(String decodedCredential) {
        requireNonNull(decodedCredential, "decodedCredential cannot be null");

        JsonNode credentialStatusNode;
        try {
            JsonNode root = objectMapper.readTree(decodedCredential);
            credentialStatusNode = root.get("credentialStatus");
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Error parsing credentialDecoded JSON", e);
        }

        if (credentialStatusNode == null || credentialStatusNode.isNull()) {
            throw new IllegalArgumentException("credentialStatus not found in credentialDecoded");
        }

        return CredentialStatus.builder()
                .id(textOrNull(credentialStatusNode, "id"))
                .type(textOrNull(credentialStatusNode, "type"))
                .statusPurpose(textOrNull(credentialStatusNode, "statusPurpose"))
                .statusListIndex(textOrNull(credentialStatusNode, "statusListIndex"))
                .statusListCredential(textOrNull(credentialStatusNode, "statusListCredential"))
                .build();
    }

    private String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        return v.asText();
    }
}
