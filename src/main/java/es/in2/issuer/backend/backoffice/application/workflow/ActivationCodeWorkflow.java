package es.in2.issuer.backend.backoffice.application.workflow;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import reactor.core.publisher.Mono;

public interface ActivationCodeWorkflow {
    Mono<CredentialOfferUriResponse> buildCredentialOfferUri(String processId, String activationCode);
    Mono<CredentialOfferUriResponse> buildNewCredentialOfferUri(String processId, String cActivationCode);
}
