package es.in2.issuer.backend.shared.domain.util;

import io.github.novacrypto.base58.Base58;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class JwtUtilsTest {

    private final JwtUtils jwtUtils = new JwtUtils();

    public String getPayload(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("invalid JWT");
        }
        return parts[1];
    }

    @Test
    void testGetPayload() {
        String jwt = "header.payload.signature";
        String payload = getPayload(jwt);
        assertEquals("payload", payload, "El payload extraído coincide");
    }

    @Test
    void testDecodePayload() {
        String jsonPayload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";
        String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(jsonPayload.getBytes());
        String jwt = "header." + encodedPayload + ".signature";
        String decodedPayload = jwtUtils.decodePayload(jwt);
        assertEquals(jsonPayload, decodedPayload, "El payload decodificado coincide");
    }

    @Test
    void testGetPayloadWithInvalidJWT() {
        String invalidJwt = "headeronly";

        Exception exception = assertThrows(IllegalArgumentException.class, () -> getPayload(invalidJwt));

        assertEquals("invalid JWT", exception.getMessage());
    }

    @Test
    void testDecodePayloadWithInvalidJWT() {
        String invalidJwt = "headeronly";

        Exception exception = assertThrows(IllegalArgumentException.class, () -> jwtUtils.decodePayload(invalidJwt));

        assertEquals("invalid JWT", exception.getMessage());
    }

    @Test
    void testGetPayloadMocked() {
        String payload = getPayload("header.payload.signature");
        assertEquals("payload", payload, "El payload extraído coincide");
    }

    @ParameterizedTest
    @MethodSource("provideJsonsForEqualityTest")
    void testAreJsonsEqual(String json1, String json2, boolean expectedResult) {
        boolean result = jwtUtils.areJsonsEqual(json1, json2);
        assertThat(result).isEqualTo(expectedResult);
    }

    private static Stream<Arguments> provideJsonsForEqualityTest() {
        return Stream.of(
                Arguments.of("{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}", "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}", true),
                Arguments.of("{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}", "{\"city\":\"New York\",\"age\":30,\"name\":\"John\"}", true),
                Arguments.of("{}", "{}", true),
                Arguments.of("{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}", "{\"name\":\"John\",\"age\":31,\"city\":\"New York\"}", false),
                Arguments.of("{\"name\":\"John\",\"age\":30}", "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}", false),
                Arguments.of("{\"name\":\"John\", \"age\":30}", "{name:\"John\", age:30}", false)
        );
    }

    @Test
    void testAreJsonsEqual_NullJsons() {
        boolean result = jwtUtils.areJsonsEqual(null, null);

        assertThat(result).isFalse();
    }

    private static String b64u(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Test
    void didKeyFromJwk_okpEd25519_buildsExpectedDidKey() {
        byte[] x = new byte[32];
        for (int i = 0; i < x.length; i++) x[i] = (byte) i;

        Map<String, Object> jwk = Map.of(
                "kty", "OKP",
                "crv", "Ed25519",
                "x", b64u(x)
        );

        String did = jwtUtils.didKeyFromJwk(jwk);

        // expected bytes = prefix2(0xED,0x01,x)
        byte[] expectedBytes = new byte[2 + x.length];
        expectedBytes[0] = (byte) 0xED;
        expectedBytes[1] = (byte) 0x01;
        System.arraycopy(x, 0, expectedBytes, 2, x.length);

        String expectedDid = "did:key:" + "z" + Base58.base58Encode(expectedBytes);
        assertThat(did).isEqualTo(expectedDid);
    }

    @Test
    void didKeyFromJwk_ecP256_buildsExpectedDidKey() {
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        for (int i = 0; i < 32; i++) {
            x[i] = (byte) (i + 1);
            y[i] = (byte) (100 + i);
        }

        Map<String, Object> jwk = Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", b64u(x),
                "y", b64u(y)
        );

        String did = jwtUtils.didKeyFromJwk(jwk);

        byte[] pub = new byte[1 + x.length + y.length];
        pub[0] = 0x04;
        System.arraycopy(x, 0, pub, 1, x.length);
        System.arraycopy(y, 0, pub, 1 + x.length, y.length);

        // multicodec = prefix2(0x12,0x00,pub)
        byte[] multicodec = new byte[2 + pub.length];
        multicodec[0] = 0x12;
        multicodec[1] = 0x00;
        System.arraycopy(pub, 0, multicodec, 2, pub.length);

        String expectedDid = "did:key:" + "z" + Base58.base58Encode(multicodec);
        assertThat(did).isEqualTo(expectedDid);
    }

    @Test
    void didKeyFromJwk_throwsWhenRequiredParamsMissing() {
        Map<String, Object> ed = Map.of("kty", "OKP", "crv", "Ed25519");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> jwtUtils.didKeyFromJwk(ed));
        assertThat(ex.getMessage()).isEqualTo("JWK missing required parameter: x");

        Map<String, Object> ecMissingY = Map.of("kty", "EC", "crv", "P-256", "x", b64u(new byte[32]));
        IllegalArgumentException ex2 = assertThrows(IllegalArgumentException.class, () -> jwtUtils.didKeyFromJwk(ecMissingY));
        assertThat(ex2.getMessage()).isEqualTo("JWK missing required parameter: y");
    }

}
