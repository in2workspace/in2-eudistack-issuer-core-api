package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
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
}
