package es.in2.issuer.backend.shared.domain.model.dto.credential;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IssuerDeserializerTest {

    private ObjectMapper getObjectMapperWithIssuerModule() {
        ObjectMapper mapper = new ObjectMapper();
        SimpleModule module = new SimpleModule();
        // Register the deserializer for the Issuer interface
        module.addDeserializer(Issuer.class, new IssuerDeserializer());
        mapper.registerModule(module);
        return mapper;
    }

    @Test
    void testDeserializeSimpleIssuer() throws Exception {
        // Case 1: JSON string -> SimpleIssuer
        String json = "\"simple-issuer-id\"";
        ObjectMapper mapper = getObjectMapperWithIssuerModule();
        Issuer issuer = mapper.readValue(json, Issuer.class);
        assertNotNull(issuer);
        assertInstanceOf(SimpleIssuer.class, issuer);
        assertEquals("simple-issuer-id", issuer.getId());
    }

    @Test
    void testDeserializeDetailedIssuer() throws Exception {
        // Case 2: JSON object -> DetailedIssuer
        String json = "{" +
                "\"id\": \"detailed-issuer-id\"," +
                "\"organizationIdentifier\": \"org-id\"," +
                "\"organization\": \"Organization\"," +
                "\"country\": \"Country\"," +
                "\"commonName\": \"Common Name\"," +
                "\"serialNumber\": \"SN123\"" +
                "}";
        ObjectMapper mapper = getObjectMapperWithIssuerModule();
        Issuer issuer = mapper.readValue(json, Issuer.class);
        assertNotNull(issuer);
        assertInstanceOf(DetailedIssuer.class, issuer);
        DetailedIssuer detailedIssuer = (DetailedIssuer) issuer;
        assertEquals("detailed-issuer-id", detailedIssuer.getId());
        assertEquals("org-id", detailedIssuer.organizationIdentifier());
        assertEquals("Organization", detailedIssuer.organization());
        assertEquals("Country", detailedIssuer.country());
        assertEquals("Common Name", detailedIssuer.commonName());
        assertEquals("SN123", detailedIssuer.serialNumber());
    }

    @Test
    void testDeserializeUnexpectedTypeThrowsException() {
        // Case 3: Unexpected data type (array) -> exception is thrown
        String json = "[\"unexpected\"]";
        ObjectMapper mapper = getObjectMapperWithIssuerModule();
        Exception exception = assertThrows(JsonMappingException.class, () -> mapper.readValue(json, Issuer.class));
        String expectedMessage = "Unexpected data type for Issuer";
        String actualMessage = exception.getMessage();
        assertTrue(actualMessage.contains(expectedMessage));
    }
}
