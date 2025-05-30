package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class UtilsTest {

    @Test
    void testGenerateCustomNonce() {
        StepVerifier.create(Utils.generateCustomNonce())
                .assertNext(nonce -> {
                    assertNotNull(nonce);
                    assertFalse(nonce.isEmpty());
                    assertDoesNotThrow(() -> Base64.getUrlDecoder().decode(nonce));
                })
                .verifyComplete();
    }

}