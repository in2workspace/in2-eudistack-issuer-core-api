package es.in2.issuer.backend.backoffice.domain.service.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.springframework.vault.core.ReactiveVaultKeyValueOperations;
import org.springframework.vault.core.ReactiveVaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
class VaultServiceImplTest {

    @Mock
    private ReactiveVaultOperations reactiveVaultOperations;

    @Mock
    private ReactiveVaultKeyValueOperations vaultOperations;

    private VaultServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new VaultServiceImpl(vaultOperations);
    }

    @Test
    void saveSecrets_delegatesToVaultPut() {
        String path = "path/to/secret";
        Map<String, String> secrets = Map.of("a", "1", "b", "2");

        when(vaultOperations.put(path, secrets)).thenReturn(Mono.empty());

        StepVerifier.create(service.saveSecrets(path, secrets))
                .verifyComplete();

        verify(vaultOperations).put(path, secrets);
    }

    @Test
    void getSecrets_returnsData() {
        String path = "some/path";
        VaultResponseSupport<Map<String, Object>> resp = mock(VaultResponseSupport.class);
        Map<String, Object> data = new HashMap<>();
        data.put("k", 123);

        when(resp.getData()).thenReturn(data);
        when(vaultOperations.get(path, (Class<Map<String, Object>>) (Class<?>) Map.class))
                .thenReturn(Mono.just(resp));

        StepVerifier.create(service.getSecrets(path))
                .assertNext(map -> assertThat(map).containsEntry("k", 123))
                .verifyComplete();

        verify(vaultOperations).get(path, (Class<Map<String, Object>>) (Class<?>) Map.class);
    }

    @Test
    void getSecrets_emptyWhenNoPath() {
        String path = "missing/path";

        when(vaultOperations.get(path, Map.class)).thenReturn(Mono.empty());

        StepVerifier.create(service.getSecrets(path))
                .verifyComplete();

        verify(vaultOperations).get(path, Map.class);
    }

    @Test
    void deleteSecret_delegatesToVaultDelete() {
        String path = "del/path";

        when(vaultOperations.delete(path)).thenReturn(Mono.empty());

        StepVerifier.create(service.deleteSecret(path))
                .verifyComplete();

        verify(vaultOperations).delete(path);
    }

    @Test
    void patchSecrets_mergesAndPuts() {
        String path = "patch/path";
        Map<String, Object> existing = new HashMap<>();
        existing.put("x", "old");
        VaultResponseSupport<Map<String, Object>> resp = mock(VaultResponseSupport.class);
        when(resp.getData()).thenReturn(existing);

        when(vaultOperations.get(path, (Class<Map<String, Object>>) (Class<?>) Map.class))
                .thenReturn(Mono.just(resp));

        Map<String, String> update = Map.of("y", "new", "x", "override");
        when(vaultOperations.put(eq(path), anyMap()))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.patchSecrets(path, update))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(vaultOperations).put(eq(path), captor.capture());

        Map<String, Object> merged = captor.getValue();

        assertThat(merged)
                .containsEntry("x", "override")
                .containsEntry("y", "new");
    }

    @Test
    void patchSecrets_onEmptyInitial_fetchesEmptyThenPutsUpdate() {
        String path = "patch/empty";

        VaultResponseSupport<Map<String, Object>> resp = mock(VaultResponseSupport.class);
        when(resp.getData()).thenReturn(new HashMap<>());
        when(vaultOperations.get(path, (Class<Map<String, Object>>) (Class<?>) Map.class))
                .thenReturn(Mono.just(resp));

        when(vaultOperations.put(eq(path), anyMap()))
                .thenReturn(Mono.empty());

        Map<String, String> update = Map.of("a", "1");

        StepVerifier.create(service.patchSecrets(path, update))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass((Class) Map.class);
        verify(vaultOperations).put(eq(path), captor.capture());

        Map<String, Object> resultMap = captor.getValue();
        assertThat(resultMap)
                .hasSize(1)
                .containsEntry("a", "1");
    }
}