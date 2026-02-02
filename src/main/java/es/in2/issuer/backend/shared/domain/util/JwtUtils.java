package es.in2.issuer.backend.shared.domain.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.novacrypto.base58.Base58;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;

@Component
@Slf4j
public class JwtUtils {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public String decodePayload(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("invalid JWT");
        }

        byte[] decodedBytes = Base64.getDecoder().decode(parts[1]);
        return new String(decodedBytes);
    }

    public boolean areJsonsEqual(String json1, String json2) {
        try {
            Map<String, Object> map1 = objectMapper.readValue(json1, Map.class);
            Map<String, Object> map2 = objectMapper.readValue(json2, Map.class);

            return map1.equals(map2);
        } catch (Exception e) {
            log.error("Error comparing JSONs", e);
            return false;
        }
    }

    public String didKeyFromJwk(Map<String, Object> jwk) {
        if (jwk == null || jwk.isEmpty()) {
            throw new IllegalArgumentException("jwk is empty");
        }

        String kty = asString(jwk.get("kty"));
        String crv = asString(jwk.get("crv"));

        if ("EC".equalsIgnoreCase(kty) && "P-256".equalsIgnoreCase(crv)) {
            // EC P-256: needs x,y
            byte[] x = b64uDecodeRequired(jwk, "x");
            byte[] y = b64uDecodeRequired(jwk, "y");

            byte[] pub = new byte[1 + x.length + y.length];
            pub[0] = 0x04;
            System.arraycopy(x, 0, pub, 1, x.length);
            System.arraycopy(y, 0, pub, 1 + x.length, y.length);

            // multicodec prefix for P-256 public key: 0x12 0x00 (as per your current did:key decoding assumptions)
            byte[] multicodec = prefix2((byte) 0x12, (byte) 0x00, pub);

            return toDidKey(multicodec);
        }

        if ("OKP".equalsIgnoreCase(kty) && "Ed25519".equalsIgnoreCase(crv)) {
            // Ed25519: x only (32 bytes)
            byte[] x = b64uDecodeRequired(jwk, "x");

            // multicodec prefix for Ed25519 public key: 0xED 0x01
            byte[] multicore = prefix2((byte) 0xED, (byte) 0x01, x);

            return toDidKey(multicore);
        }

        throw new IllegalArgumentException("Unsupported JWK for did:key: kty=" + kty + ", crv=" + crv);
    }

    private static String toDidKey(byte[] multicorePrefixedKey) {
        String mb58 = "z" + Base58.base58Encode(multicorePrefixedKey);
        return "did:key:" + mb58;
    }

    private static byte[] prefix2(byte p0, byte p1, byte[] data) {
        byte[] out = new byte[2 + data.length];
        out[0] = p0;
        out[1] = p1;
        System.arraycopy(data, 0, out, 2, data.length);
        return out;
    }

    private static byte[] b64uDecodeRequired(Map<String, Object> jwk, String key) {
        Object v = jwk.get(key);
        if (!(v instanceof String s) || s.isBlank()) {
            throw new IllegalArgumentException("JWK missing required parameter: " + key);
        }
        return Base64.getUrlDecoder().decode(s);
    }

    private static String asString(Object v) {
        return (v instanceof String s && !s.isBlank()) ? s : null;
    }

}