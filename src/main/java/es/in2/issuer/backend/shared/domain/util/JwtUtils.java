// JwtUtils.java
package es.in2.issuer.backend.shared.domain.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@Slf4j
public class JwtUtils {

    public String decodePayload(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("invalid JWT");
        }
        String payloadPart = parts[1];

        // JWT usa Base64URL sense padding. Normalitzem i decode URL-safe.
        String normalized = normalizeBase64Url(payloadPart);
        byte[] decodedBytes = Base64.getUrlDecoder().decode(normalized);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    private static String normalizeBase64Url(String s) {
        int mod = s.length() % 4;
        if (mod != 0) {
            s = s + "====".substring(mod);
        }
        return s;
    }

    public boolean areJsonsEqual(String json1, String json2) {
        if (json1 == null || json2 == null) {
            return false;
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode n1 = mapper.readTree(json1);
            JsonNode n2 = mapper.readTree(json2);
            return n1 != null && n1.equals(n2);
        } catch (Exception e) {
            log.error("Error comparing JSONs", e);
            return false;
        }
    }
}
