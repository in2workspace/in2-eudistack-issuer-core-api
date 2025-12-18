package es.in2.issuer.backend.backoffice.application.workflow.policies;

import reactor.core.publisher.Mono;

public interface BackofficePdpService {

    Mono<Void> validateSignCredential(String processId, String token, String credentialProcedureId);

    Mono<Void> validateRevokeCredential(String processId, String token, String credentialProcedureId);

    Mono<Void> validateSendReminder(String processId, String token, String credentialProcedureId);
}
