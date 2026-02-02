package es.in2.issuer.backend.statuslist.application.policies;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import reactor.core.publisher.Mono;

public interface StatusListPdpService {

    Mono<Void> validateRevokeCredential(String processId, String token, CredentialProcedure procedure);
    Mono<Void> validateRevokeCredentialSystem(String processId, CredentialProcedure procedure);
}

