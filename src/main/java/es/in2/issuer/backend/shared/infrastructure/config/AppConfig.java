package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.adapter.ConfigAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.adapter.factory.ConfigAdapterFactory;
import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.IssuerIdentityProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class AppConfig {

    private final ConfigAdapter configAdapter;
    private final AppProperties appProperties;
    private final IssuerIdentityProperties issuerIdentityProperties;
    private final CorsProperties corsProperties;

    public AppConfig(
            ConfigAdapterFactory configAdapterFactory,
            AppProperties appProperties,
            IssuerIdentityProperties issuerIdentityProperties,
            CorsProperties corsProperties
    ) {
        this.configAdapter = configAdapterFactory.getAdapter();
        this.appProperties = appProperties;
        this.issuerIdentityProperties = issuerIdentityProperties;
        this.corsProperties = corsProperties;
    }

    public String getIssuerBackendUrl() {
        return configAdapter.getConfiguration(appProperties.url());
    }

    public String getIssuerFrontendUrl() {
        return configAdapter.getConfiguration(appProperties.issuerFrontendUrl());
    }

    public String getKnowledgebaseWalletUrl() {
        return configAdapter.getConfiguration(appProperties.knowledgeBase().walletGuideUrl());
    }

    public String getWalletFrontendUrl() {
        return configAdapter.getConfiguration(appProperties.walletUrl());
    }

    public String getKnowledgeBaseUploadCertificationGuideUrl() {
        return configAdapter.getConfiguration(appProperties.knowledgeBase().uploadCertificationGuideUrl());
    }

    public String getConfigSource() {
        return configAdapter.getConfiguration(appProperties.configSource());
    }

    public String getCredentialSubjectDidKey() {
        return issuerIdentityProperties.credentialSubjectDidKey();
    }

    public String getJwtCredential() {
        return issuerIdentityProperties.jwtCredential();
    }

    public String getCryptoPrivateKey() {
        return issuerIdentityProperties.crypto().privateKey();
    }

    public List<String> getExternalCorsAllowedOrigins() {
        return corsProperties.externalAllowedOrigins();
    }
    public List<String> getDefaultCorsAllowedOrigins() {
        return corsProperties.defaultAllowedOrigins();
    }

    public String getTrustFrameworkUrl() {
        return configAdapter.getConfiguration(appProperties.trustFrameworkUrl());
    }

    public String getVerifierUrl() {
        return configAdapter.getConfiguration(appProperties.verifierUrl());
    }
}
