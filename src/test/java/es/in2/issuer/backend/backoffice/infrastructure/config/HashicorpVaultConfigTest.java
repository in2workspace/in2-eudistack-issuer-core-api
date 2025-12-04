package es.in2.issuer.backend.backoffice.infrastructure.config;

import es.in2.issuer.backend.backoffice.infrastructure.config.properties.HashicorpVaultProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.ReactiveVaultKeyValueOperations;
import org.springframework.vault.core.ReactiveVaultOperations;
import org.springframework.vault.core.VaultKeyValueOperationsSupport;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HashicorpVaultConfigTest {

    @Mock
    private HashicorpVaultProperties properties;

    @InjectMocks
    private HashicorpVaultConfig config;

    @Mock
    private ReactiveVaultOperations reactiveVaultOperations;

    @Mock
    private ReactiveVaultKeyValueOperations keyValueOperations;

    @Test
    void kvOperationsShouldUseSecretsMountAndKv2Backend() {
        // given
        String mount = "secret-mount";
        when(properties.secretsMount()).thenReturn(mount);
        when(reactiveVaultOperations.opsForKeyValue(
                mount,
                VaultKeyValueOperationsSupport.KeyValueBackend.KV_2
        )).thenReturn(keyValueOperations);

        // when
        ReactiveVaultKeyValueOperations result =
                config.kvOperations(reactiveVaultOperations, properties);

        // then
        assertSame(keyValueOperations, result, "Returned KV operations must be the one provided by ReactiveVaultOperations");
        verify(reactiveVaultOperations).opsForKeyValue(
                mount,
                VaultKeyValueOperationsSupport.KeyValueBackend.KV_2
        );
        verify(properties, times(1)).secretsMount();
    }

    @Test
    void vaultEndpointShouldBeCreatedFromPropertiesUrl() {
        // given
        String url = "http://localhost:8200";
        when(properties.url()).thenReturn(url);

        // when
        VaultEndpoint endpoint = config.vaultEndpoint();

        // then
        assertEquals("localhost", endpoint.getHost());
        assertEquals(8200, endpoint.getPort());
        assertEquals("http", endpoint.getScheme());
        verify(properties).url();
    }

    @Test
    void clientAuthenticationShouldCreateTokenAuthentication() {
        // given
        when(properties.token()).thenReturn("any-token");

        // when
        ClientAuthentication clientAuthentication = config.clientAuthentication();

        // then
        assertNotNull(clientAuthentication);
        assertTrue(clientAuthentication instanceof TokenAuthentication);
        verify(properties).token();
    }

    @Test
    void decodeIfBase64ShouldDecodeValidBase64() throws Exception {
        // given
        String rawToken = "my-very-secret-token";
        String base64Token = Base64.getEncoder()
                .encodeToString(rawToken.getBytes(StandardCharsets.UTF_8));

        // when
        String decoded = invokeDecodeIfBase64(base64Token);

        // then
        assertEquals(rawToken, decoded);
    }

    @Test
    void decodeIfBase64ShouldTrimPlainToken() throws Exception {
        // given
        String tokenWithSpaces = "  plain-token-value  ";

        // when
        String decoded = invokeDecodeIfBase64(tokenWithSpaces);

        // then
        assertEquals("plain-token-value", decoded);
    }

    private String invokeDecodeIfBase64(String token) throws Exception {
        // Use reflection to call private method decodeIfBase64(String)
        Method method = HashicorpVaultConfig.class
                .getDeclaredMethod("decodeIfBase64", String.class);
        method.setAccessible(true);
        Object result = method.invoke(config, token);
        return (String) result;
    }
}
