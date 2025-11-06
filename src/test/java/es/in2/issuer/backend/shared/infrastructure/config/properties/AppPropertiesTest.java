package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AppPropertiesTest {

    @Test
    void appProperties_initializesCorrectly() {
        String appUrl = "https://app-url.com";
        String issuerFrontendUrl = "https://issuer-frontend-url.com";
        String trustFrameworkUrl = "https://trust-framework-url.com";
        String verifierUrl = "https://verifier-url.com";
        String configSource = "configSource";
        String walletFrontendUrl = "https://wallet-frontend-url.com";
        String defaultLang = "es";
        String adminOrganizationId = "org-admin";
        String sysTenant = "sys-tenant";

        String uploadGuideUrl = "https://upload-guide-url.com";
        String walletGuideUrl = "https://wallet-guide-url.com";

        AppProperties.KnowledgeBase knowledgeBase =
                new AppProperties.KnowledgeBase(uploadGuideUrl, walletGuideUrl);

        // Act
        AppProperties appProperties = new AppProperties(
                appUrl,
                issuerFrontendUrl,
                trustFrameworkUrl,
                knowledgeBase,
                verifierUrl,
                configSource,
                walletFrontendUrl,
                defaultLang,
                adminOrganizationId,
                sysTenant
        );

        // Assert
        assertEquals(appUrl, appProperties.url());
        assertEquals(issuerFrontendUrl, appProperties.issuerFrontendUrl());
        assertEquals(trustFrameworkUrl, appProperties.trustFrameworkUrl());
        assertEquals(knowledgeBase, appProperties.knowledgeBase());
        assertEquals(verifierUrl, appProperties.verifierUrl());
        assertEquals(configSource, appProperties.configSource());
        assertEquals(walletFrontendUrl, appProperties.walletUrl());
        assertEquals(sysTenant, appProperties.sysTenant());
        assertEquals(adminOrganizationId, appProperties.adminOrganizationId());
    }

    @Test
    void knowledgeBase_initializesCorrectly() {
        // Arrange
        String uploadGuideUrl = "https://upload-guide-url.com";
        String walletGuideUrl = "https://wallet-guide-url.com";

        // Act
        AppProperties.KnowledgeBase knowledgeBase =
                new AppProperties.KnowledgeBase(uploadGuideUrl, walletGuideUrl);

        // Assert
        assertEquals(uploadGuideUrl, knowledgeBase.uploadCertificationGuideUrl());
        assertEquals(walletGuideUrl, knowledgeBase.walletGuideUrl());
    }
}
