package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.backoffice.domain.model.dtos.CompleteSignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigWithProviderName;
import es.in2.issuer.backend.backoffice.domain.model.dtos.SignatureConfigurationResponse;
import es.in2.issuer.backend.backoffice.domain.model.entities.SignatureConfiguration;
import es.in2.issuer.backend.backoffice.domain.model.enums.SignatureMode;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

public interface SignatureConfigurationService {
    Mono<SignatureConfiguration> saveSignatureConfig(CompleteSignatureConfiguration config, String organizationIdentifier);
    Mono<Map<String,Object>> getSignatureCredentials(String secretRelativePath);
    Flux<SignatureConfigWithProviderName> findAllByOrganizationIdentifierAndMode(String organizationIdentifier, SignatureMode signatureMode);
    Mono<SignatureConfigurationResponse> getCompleteConfigurationById(String id, String organizationId);
    Mono<Void> updateSignatureConfiguration(String id, String organizationId, CompleteSignatureConfiguration config , String rationale ,String userEmail);
    Mono<Void> deleteSignatureConfiguration(String id, String organizationId, String rationale, String userEmail);
}
