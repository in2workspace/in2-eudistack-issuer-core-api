package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureIdAndTxCode;
import es.in2.issuer.backend.shared.domain.model.dto.Grants;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.security.SecureRandom;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_CODE_SIZE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_INPUT_MODE;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class PreAuthorizedCodeServiceImplTest {

    @Mock
    private SecureRandom random; // Unused in these tests, needed by constructor
    @Mock
    private CacheStore<CredentialProcedureIdAndTxCode> cacheStore; // Unused here
    @Mock
    private TranslationService translationService; // Unused here

    private PreAuthorizedCodeServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new PreAuthorizedCodeServiceImpl(random, cacheStore, translationService);
    }

    @Test
    void buildPreAuthorizedCodeResponse_createsExpectedPayload() throws Exception {
        // Given
        String preAuthorizedCode = "pre-auth-abc123";
        String txCode = "567890";

        // When
        Mono<PreAuthorizedCodeResponse> mono = invokeBuild(preAuthorizedCode, txCode);

        // Then
        StepVerifier.create(mono)
                .assertNext(resp -> {
                    assertNotNull(resp, "Response must not be null");
                    // PreAuthorizedCodeResponse(pin=..., grants=...)
                    assertEquals(txCode, resp.pin(), "pin in response must match input txCode");

                    Grants grants = resp.grants();
                    assertNotNull(grants, "grants must not be null");
                    assertEquals(preAuthorizedCode, grants.preAuthorizedCode(),
                            "preAuthorizedCode in grants must match input");

                    Grants.TxCode grantTx = grants.txCode();
                    assertNotNull(grantTx, "grants.txCode must not be null");
                    assertEquals(TX_CODE_SIZE, grantTx.length(),
                            "TxCode.length must match TX_CODE_SIZE");
                    assertEquals(TX_INPUT_MODE, grantTx.inputMode(),
                            "TxCode.inputMode must match TX_INPUT_MODE");
                    // Not set in service; should be null
                    assertNull(grantTx.description(), "TxCode.description should be null");
                })
                .verifyComplete();
    }

    @Test
    void buildPreAuthorizedCodeResponse_emitsSingleValueAndCompletes() throws Exception {
        // Given
        String preAuthorizedCode = "pre-auth-xyz789";
        String txCode = "123456";

        // When
        Mono<PreAuthorizedCodeResponse> mono = invokeBuild(preAuthorizedCode, txCode);

        // Then
        StepVerifier.create(mono)
                .expectNextCount(1)
                .verifyComplete();
    }

    // --- Helper to call the private method via reflection ---

    @SuppressWarnings("unchecked")
    private Mono<PreAuthorizedCodeResponse> invokeBuild(String preAuthorizedCode, String txCode) throws Exception {
        Method m = PreAuthorizedCodeServiceImpl.class
                .getDeclaredMethod("buildPreAuthorizedCodeResponse", String.class, String.class);
        m.setAccessible(true);
        return (Mono<PreAuthorizedCodeResponse>) m.invoke(service, preAuthorizedCode, txCode);
    }

    @Test
    void buildPreAuthorizedCodeResponse_shouldBuildTxCodeProperly() throws Exception {
        // Given
        String preAuthorizedCode = "pre-auth-sonar";
        String txCode = "999999";

        // When
        Mono<PreAuthorizedCodeResponse> mono = invokeBuild(preAuthorizedCode, txCode);
        PreAuthorizedCodeResponse response = mono.block(); // Forces execution of Mono.just(...)

        // Then
        assertNotNull(response, "Response must not be null");
        Grants.TxCode grantTx = response.grants().txCode();
        assertNotNull(grantTx, "TxCode must not be null");
        assertEquals(TX_CODE_SIZE, grantTx.length(), "Should match TX_CODE_SIZE constant");
        assertEquals(TX_INPUT_MODE, grantTx.inputMode(), "Should match TX_INPUT_MODE constant");
    }
}
