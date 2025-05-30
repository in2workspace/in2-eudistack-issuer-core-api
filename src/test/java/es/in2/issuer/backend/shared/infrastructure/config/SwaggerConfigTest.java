package es.in2.issuer.backend.shared.infrastructure.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SwaggerConfigTest {

    private SwaggerConfig swaggerConfig;

    @BeforeEach
    public void setUp() {
        // Manually instantiate the SwaggerConfig
        swaggerConfig = new SwaggerConfig();
    }

    @Test
    void testPublicApiGroupedOpenApiNotNull() {
        GroupedOpenApi publicApi = swaggerConfig.publicApi();
        assertNotNull(publicApi, "Public API GroupedOpenApi should not be null");
    }

    @Test
    void testPrivateApiGroupedOpenApiNotNull() {
        GroupedOpenApi privateApi = swaggerConfig.privateApi();
        assertNotNull(privateApi, "Private API GroupedOpenApi should not be null");
    }

    @Test
    void testTagOpenApiCustomizerRemovesUnwantedTagsWithReflection() throws Exception {
        // Arrange
        OpenAPI openAPI = new OpenAPI();
        Paths paths = new Paths();
        PathItem pathItem1 = new PathItem();
        Operation operation1 = new Operation();
        operation1.setTags(List.of("Public"));
        pathItem1.setGet(operation1);

        PathItem pathItem2 = new PathItem();
        Operation operation2 = new Operation();
        operation2.setTags(List.of("Private"));
        pathItem2.setPost(operation2);

        PathItem pathItem3 = new PathItem();
        Operation operation3 = new Operation();
        operation3.setTags(List.of("Other"));
        pathItem3.setPut(operation3);

        paths.addPathItem("/path1", pathItem1);
        paths.addPathItem("/path2", pathItem2);
        paths.addPathItem("/path3", pathItem3);

        openAPI.setPaths(paths);

        Method method = SwaggerConfig.class.getDeclaredMethod("tagOpenApiCustomizer", Set.class);
        method.setAccessible(true);
        OpenApiCustomizer customizer = (OpenApiCustomizer) method.invoke(swaggerConfig, Set.of(SwaggerConfig.TAG_PUBLIC, SwaggerConfig.TAG_PRIVATE));

        // Act
        customizer.customise(openAPI);

        // Assert
        assertNotNull(openAPI.getPaths().get("/path1").getGet(), "Operation with 'Public' tag should not be removed");
        assertNotNull(openAPI.getPaths().get("/path2").getPost(), "Operation with 'Private' tag should not be removed");
        assertFalse(openAPI.getPaths().containsKey("/path3"), "Operation with 'Other' tag should be removed");
        assertFalse(openAPI.getPaths().containsKey("/path3"), "Path with no matching operations should be removed");
    }
}