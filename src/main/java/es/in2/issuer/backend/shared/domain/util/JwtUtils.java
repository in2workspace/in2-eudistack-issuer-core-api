package es.in2.issuer.backend.shared.domain.util;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

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
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> map1 = objectMapper.readValue(json1, Map.class);
            Map<String, Object> map2 = objectMapper.readValue(json2, Map.class);

            return map1.equals(map2);
        } catch (Exception e) {
            log.error("Error comparing JSONs", e);
            return false;
        }
    }

    // Keep the record as-is
    public record TokenEmailAndOrg(String organizationIdentifier, String email) {}

    /**
     * Extracts:
     *  - email from vc.credentialSubject.mandate.mandatee.email
     *  - organizationIdentifier from vc.credentialSubject.mandate.mandator.organizationIdentifier
     */
    public TokenEmailAndOrg extractTokenEmailAndOrg(String token) {
        try {
            JWSObject jws = JWSObject.parse(token);
            String payloadJson = jws.getPayload().toString();
            JsonNode root = objectMapper.readTree(payloadJson);

            JsonNode mandateNode = root
                    .path("vc")
                    .path("credentialSubject")
                    .path("mandate");

            if (!mandateNode.isObject()) {
                log.debug("No mandate node found in token");
                return null;
            }

            // Extract mandatee email
            String email = mandateNode.path("mandatee").path("email").asText(null);

            // Extract mandator organizationIdentifier
            String organizationIdentifier = mandateNode
                    .path("mandator")
                    .path("organizationIdentifier")
                    .asText(null);

            if ((email == null || email.isBlank()) &&
                    (organizationIdentifier == null || organizationIdentifier.isBlank())) {
                return null;
            }

            return new TokenEmailAndOrg(email, organizationIdentifier);
        } catch (Exception e) {
            log.warn("Could not extract token mandatee email and mandator organizationIdentifier", e);
            return null;
        }
    }

}