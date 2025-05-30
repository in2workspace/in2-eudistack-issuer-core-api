package es.in2.issuer.backend.backoffice.infrastructure.config;

import es.in2.issuer.backend.backoffice.infrastructure.config.properties.OpenApiProperties;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OpenAppConfigTest {

    @Mock
    private OpenApiProperties openApiProperties;

    @Mock
    private AppConfig appConfig;

    private OpenApiConfig openApiConfig;

    @BeforeEach
    void setUp() {
        openApiConfig = new OpenApiConfig(openApiProperties, appConfig);
    }

    @Test
    void testOpenApiConfiguration() {
        // Mock properties
        OpenApiProperties.OpenApiInfoProperties.OpenApiInfoContactProperties contactProperties = new OpenApiProperties.OpenApiInfoProperties.OpenApiInfoContactProperties("test@example.com", "John Doe", "http://example.com");
        OpenApiProperties.OpenApiInfoProperties.OpenApiInfoLicenseProperties licenseProperties = new OpenApiProperties.OpenApiInfoProperties.OpenApiInfoLicenseProperties("Apache 2.0", "https://www.apache.org/licenses/LICENSE-2.0");
        OpenApiProperties.OpenApiInfoProperties infoProperties = new OpenApiProperties.OpenApiInfoProperties("Test API", "1.0", "Test Description", "http://example.com/tos", contactProperties, licenseProperties);
        when(openApiProperties.info()).thenReturn(infoProperties);
        OpenApiProperties.OpenApiServerProperties serverProperties = new OpenApiProperties.OpenApiServerProperties("Test Server", "Test Description");
        when(openApiProperties.server()).thenReturn(serverProperties);

        // Invoke method to test
        OpenAPI openAPI = openApiConfig.openApi();

        // Assertions
        assertNotNull(openAPI);
        Info info = openAPI.getInfo();
        assertNotNull(info);
        Contact contact = info.getContact();
        assertNotNull(contact);
        License license = info.getLicense();
        assertNotNull(license);
        assertEquals("Test API", info.getTitle());
        assertEquals("1.0", info.getVersion());
        assertEquals("John Doe", contact.getName());
        assertEquals("test@example.com", contact.getEmail());
        assertEquals("http://example.com", contact.getUrl());
        assertEquals("Apache 2.0", license.getName());
        assertEquals("https://www.apache.org/licenses/LICENSE-2.0", license.getUrl());
        assertEquals(1, openAPI.getServers().size());
        Server server = openAPI.getServers().get(0);
        assertNotNull(server);
        assertEquals("Test Description", server.getDescription());
    }
}