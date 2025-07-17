package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.GetCredentialIssuerMetadataWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class GetCredentialIssuerMetadataWorkflowImpl implements GetCredentialIssuerMetadataWorkflow {

    private final CredentialIssuerMetadataService credentialIssuerMetadataService;

    @Override
    public Mono<CredentialIssuerMetadata> execute(String processId) {
        return credentialIssuerMetadataService.getCredentialIssuerMetadata(processId);
    }

}
