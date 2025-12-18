package es.in2.issuer.backend.backoffice.infrastructure.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class HashicorpVaultPropertiesTest {

    @Configuration
    @EnableConfigurationProperties(HashicorpVaultProperties.class)
    static class TestConfig {
        // Empty on purpose. Only used to register HashicorpVaultProperties.
    }

    @Test
    void whenAllPropertiesPresent_contextStartsAndBindsCorrectly() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "vault.hashicorp.url=https://vault.example.com",
                        "vault.hashicorp.token=my-token",
                        "vault.hashicorp.secrets-mount=kv"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();

                    HashicorpVaultProperties props = context.getBean(HashicorpVaultProperties.class);

                    assertThat(props.url()).isEqualTo("https://vault.example.com");
                    assertThat(props.token()).isEqualTo("my-token");
                    assertThat(props.secretsMount()).isEqualTo("kv");
                });
    }

    @Test
    void whenTokenMissing_contextFails() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "vault.hashicorp.url=https://vault.example.com",
                        // missing token
                        "vault.hashicorp.secrets-mount=kv"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void whenSecretsMountMissing_contextFails() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "vault.hashicorp.url=https://vault.example.com",
                        "vault.hashicorp.token=my-token"
                        // missing secrets-mount
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void whenUrlInvalid_contextFails() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "vault.hashicorp.url=not-a-valid-url",
                        "vault.hashicorp.token=my-token",
                        "vault.hashicorp.secrets-mount=kv"
                )
                .run(context -> assertThat(context).hasFailed());
    }
}
