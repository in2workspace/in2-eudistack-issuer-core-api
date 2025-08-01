package es.in2.issuer.backend.shared.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "app")
@Validated
public record AppProperties(
        @NotBlank @URL String url,
        @NotBlank @URL String issuerFrontendUrl,
        @NotBlank @URL String trustFrameworkUrl,
        @NotNull KnowledgeBase knowledgeBase,
        @NotBlank @URL String verifierUrl,
        @NotBlank String configSource,
        @NotBlank @URL String walletUrl
) {

    @ConstructorBinding
    public AppProperties(
            String url,
            String issuerFrontendUrl,
            String trustFrameworkUrl,
            KnowledgeBase knowledgeBase,
            String verifierUrl,
            String configSource,
            String walletUrl
    ) {
        this.url = url;
        this.issuerFrontendUrl = issuerFrontendUrl;
        this.trustFrameworkUrl = trustFrameworkUrl;
        this.knowledgeBase = knowledgeBase;
        this.verifierUrl = verifierUrl;
        this.configSource = configSource;
        this.walletUrl = walletUrl;
    }

    @Validated
    public record KnowledgeBase(
            @NotBlank @URL String uploadCertificationGuideUrl,
            @NotBlank @URL String walletGuideUrl
    ) {
    }
}
