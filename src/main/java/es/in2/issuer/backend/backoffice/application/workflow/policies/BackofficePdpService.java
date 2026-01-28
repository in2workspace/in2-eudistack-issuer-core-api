package es.in2.issuer.backend.backoffice.application.workflow.policies;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import reactor.core.publisher.Mono;

public interface BackofficePdpService {

    Mono<Void> validateSignCredential(String processId, String token, CredentialProcedure procedure);

    Mono<Void> validateSendReminder(String processId, String token, String credentialProcedureId);
}
