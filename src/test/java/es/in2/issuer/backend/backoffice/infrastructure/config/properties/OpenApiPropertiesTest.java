package es.in2.issuer.backend.backoffice.infrastructure.config.properties;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OpenApiPropertiesTest {

    private static OpenApiProperties.@NotNull OpenApiInfoProperties getOpenApiInfoProperties() {
        OpenApiProperties.OpenApiInfoProperties.OpenApiInfoContactProperties openApiInfoContactProperties = new OpenApiProperties.OpenApiInfoProperties.OpenApiInfoContactProperties("email", "name", "url");
        OpenApiProperties.OpenApiInfoProperties.OpenApiInfoLicenseProperties openApiInfoLicenseProperties = new OpenApiProperties.OpenApiInfoProperties.OpenApiInfoLicenseProperties("name", "url");
        return new OpenApiProperties.OpenApiInfoProperties("title", "version", "description", "termsOfService", openApiInfoContactProperties, openApiInfoLicenseProperties);
    }

    @Test
    void testOpenApiProperties() {
        OpenApiProperties.OpenApiServerProperties openApiServerProperties = new OpenApiProperties.OpenApiServerProperties("url", "description");
        OpenApiProperties.OpenApiInfoProperties openApiInfoProperties = getOpenApiInfoProperties();
        OpenApiProperties openApiProperties = new OpenApiProperties(openApiServerProperties, openApiInfoProperties);

        assertEquals(openApiServerProperties, openApiProperties.server());
        assertEquals(openApiInfoProperties, openApiProperties.info());
    }
}