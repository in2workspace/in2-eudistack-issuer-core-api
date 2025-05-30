package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.PendingCredentials;
import es.in2.issuer.backend.shared.domain.model.dto.SignedCredentials;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class DeferredCredentialWorkflowImpl implements DeferredCredentialWorkflow {

    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final ObjectMapper objectMapper;
    private final EmailService emailService;

    @Override
    public Mono<PendingCredentials> getPendingCredentialsByOrganizationId(String organizationId) {
        return credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationId)
                .map(decodedCredential -> PendingCredentials.CredentialPayload.builder()
                        .credential(decodedCredential)
                        .build())
                .collectList()
                .map(PendingCredentials::new);
    }

    @Override
    public Mono<Void> updateSignedCredentials(SignedCredentials signedCredentials) {
        return Flux.fromIterable(signedCredentials.credentials())
                .flatMap(sc -> processCredential(sc.credential()))
                .then();
    }

    private Mono<Void> processCredential(String jwt) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            String payload = signedJWT.getPayload().toString();
            log.debug("Credential payload: {}", payload);
            JsonNode credentialNode = objectMapper.readTree(payload);
            String credentialId = credentialNode.get(VC).get("id").asText();

            return credentialProcedureService
                    .updatedEncodedCredentialByCredentialId(jwt, credentialId)
                    .flatMap(procId ->
                            deferredCredentialMetadataService.updateVcByProcedureId(jwt, procId)
                                    .then(deferredCredentialMetadataService.getOperationModeByProcedureId(procId))
                                    .filter(ASYNC::equals)
                                    .flatMap(mode -> {
                                        NotificationData data = buildNotificationData(credentialNode);
                                        return emailService.sendCredentialSignedNotification(
                                                data.email,
                                                "Credential Ready",
                                                data.firstName,
                                                data.additionalInfo
                                        );
                                    })
                    );
        } catch (Exception e) {
            return Mono.error(new RuntimeException("Failed to process signed credential", e));
        }
    }

    private NotificationData buildNotificationData(JsonNode credentialNode) {
        JsonNode vcNode = credentialNode.has(VC) ? credentialNode.get(VC) : credentialNode;
        JsonNode subj = vcNode.path(CREDENTIAL_SUBJECT);

        NotificationData d = new NotificationData();
        if (subj.has(MANDATE) && subj.get(MANDATE).has(MANDATEE)) {
            JsonNode m = subj.get(MANDATE).get(MANDATEE);
            d.email     = m.path(EMAIL).asText(null);
            d.firstName = m.path(FIRST_NAME).asText(null);
            d.additionalInfo  = "You can now use it with your Wallet.";
        } else if (subj.has("company")) {
            JsonNode c = subj.get("company");
            d.email     = c.path(EMAIL).asText(null);
            d.firstName = c.path("commonName").asText(null);
            d.additionalInfo  = "It is now ready to be applied to your product.";
        }

        if (d.email == null || d.firstName == null) {
            log.error("Missing email or firstName in credential subject. Skipping email notification.");
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Missing required credentialSubject properties: email and firstName"
            );
        }
        return d;
    }

    private static class NotificationData {
        String email;
        String firstName;
        String additionalInfo;
    }


}
