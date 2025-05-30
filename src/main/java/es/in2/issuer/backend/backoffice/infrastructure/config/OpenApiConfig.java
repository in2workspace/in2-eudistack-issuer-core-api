package es.in2.issuer.backend.backoffice.infrastructure.config;

import es.in2.issuer.backend.backoffice.infrastructure.config.properties.OpenApiProperties;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.servers.Server;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Slf4j
@Configuration
@SecurityScheme(
        name = OpenApiConfig.BEARER_AUTHENTICATION,
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
public class OpenApiConfig {

    public static final String BEARER_AUTHENTICATION = "bearer_authentication";

    private final OpenApiProperties openApiProperties;
    private final String openApiServerUrl;

    public OpenApiConfig(OpenApiProperties openApiProperties, AppConfig appConfig) {
        this.openApiProperties = openApiProperties;
        this.openApiServerUrl = appConfig.getIssuerBackendUrl();
    }

    @Bean
    public OpenAPI openApi() {
        return new OpenAPI()
                .info(new Info().title(openApiProperties.info().title()).version(openApiProperties.info().version())
                        .contact(new Contact()
                                .email(openApiProperties.info().contact().email())
                                .name(openApiProperties.info().contact().name())
                                .url(openApiProperties.info().contact().url()))
                        .license(new License()
                                .name(openApiProperties.info().license().name())
                                .url(openApiProperties.info().license().url())))
                .servers(List.of(new Server()
                        .url(HttpUtils.ensureUrlHasProtocol(openApiServerUrl))
                        .description(openApiProperties.server().description())))
                .addSecurityItem(new SecurityRequirement()
                        .addList(BEARER_AUTHENTICATION));
    }

}
