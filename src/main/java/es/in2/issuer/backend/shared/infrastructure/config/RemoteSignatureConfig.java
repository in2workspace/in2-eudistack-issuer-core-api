package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.adapter.ConfigAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.adapter.factory.ConfigAdapterFactory;
import es.in2.issuer.backend.shared.infrastructure.config.properties.RemoteSignatureProperties;
import org.springframework.stereotype.Component;

@Component
public class RemoteSignatureConfig {

    private final ConfigAdapter configAdapter;
    private final RemoteSignatureProperties remoteSignatureProperties;

    public RemoteSignatureConfig(ConfigAdapterFactory configAdapterFactory, RemoteSignatureProperties remoteSignatureProperties) {
        this.configAdapter = configAdapterFactory.getAdapter();
        this.remoteSignatureProperties = remoteSignatureProperties;
    }

    public String getRemoteSignatureDomain() {
        return "https://adsffdsfdsasdf.ace-api.digitelts.com";
//        todo return configAdapter.getConfiguration(remoteSignatureProperties.url());
    }

    public String getRemoteSignatureSignPath() {
        return configAdapter.getConfiguration(remoteSignatureProperties.paths().signPath());
    }

    public String getRemoteSignatureClientId() {
        return configAdapter.getConfiguration(remoteSignatureProperties.clientId());
    }

    public String getRemoteSignatureClientSecret() {
        return configAdapter.getConfiguration(remoteSignatureProperties.clientSecret());
    }

    public String getRemoteSignatureCredentialId() {
        return configAdapter.getConfiguration(remoteSignatureProperties.credentialId());
    }

    public String getRemoteSignatureCredentialPassword() {
        return configAdapter.getConfiguration(remoteSignatureProperties.credentialPassword());
    }

    public String getRemoteSignatureType() {
        return configAdapter.getConfiguration(remoteSignatureProperties.type());
    }
    
}
