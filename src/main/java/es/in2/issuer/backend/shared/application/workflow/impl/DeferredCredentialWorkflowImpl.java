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
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.ASYNC;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.CREDENTIAL_READY;

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
    public Mono<Void> updateSignedCredentials(SignedCredentials signedCredentials, String procedureId) {
        return Flux.fromIterable(signedCredentials.credentials())
                .flatMap(sc -> processCredential(sc.credential(), procedureId))
                .then();
    }

    private Mono<Void> processCredential(String jwt, String procedureId) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            String payload = signedJWT.getPayload().toString();
            log.debug("Credential payload: {}", payload);
            JsonNode credentialNode = objectMapper.readTree(payload);

            return credentialProcedureService
                    .updatedEncodedCredentialByCredentialProcedureId(jwt, procedureId)
                    .flatMap(procId ->
                            deferredCredentialMetadataService.updateVcByProcedureId(jwt, procId)
                                    .then(deferredCredentialMetadataService.getOperationModeByProcedureId(procId))
                                    .filter(ASYNC::equals)
                                    .flatMap(mode -> credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procId)
                                            .flatMap( emailInfo -> emailService.sendCredentialSignedNotification(
                                            emailInfo.email(),
                                            CREDENTIAL_READY,
                                            emailInfo.organization()
                                    )))
                    );
        } catch (Exception e) {
            return Mono.error(new RuntimeException("Failed to process signed credential", e));
        }
    }
}
