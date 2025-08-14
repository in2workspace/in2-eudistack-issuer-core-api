package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AppPropertiesTest {

    @Test
    void appProperties_initializesCorrectly() {
        AppProperties.KnowledgeBase knowledgeBase = new AppProperties.KnowledgeBase("https://upload-guide-url.com", "https://wallet-guide-url.com");
        AppProperties appProperties = new AppProperties(
                "https://app-url.com",
                "https://issuer-frontend-url.com",
                "https://trust-framework-url.com",
                knowledgeBase,
                "https://verifier-url.com",
                "configSource",
                "https://wallet-frontend-url.com"
        );

        assertEquals("https://app-url.com", appProperties.url());
        assertEquals("https://issuer-frontend-url.com", appProperties.issuerFrontendUrl());
        assertEquals("https://trust-framework-url.com", appProperties.trustFrameworkUrl());
        assertEquals(knowledgeBase, appProperties.knowledgeBase());
        assertEquals("https://verifier-url.com", appProperties.verifierUrl());
        assertEquals("configSource", appProperties.configSource());
        assertEquals("https://wallet-frontend-url.com", appProperties.walletUrl());
    }

    @Test
    void knowledgeBase_initializesCorrectly() {
        AppProperties.KnowledgeBase knowledgeBase = new AppProperties.KnowledgeBase("https://upload-guide-url.com", "https://wallet-guide-url.com");

        assertEquals("https://upload-guide-url.com", knowledgeBase.uploadCertificationGuideUrl());
        assertEquals("https://wallet-guide-url.com", knowledgeBase.walletGuideUrl());
    }
}