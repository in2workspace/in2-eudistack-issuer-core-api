package es.in2.issuer.backend.statuslist.domain.factory;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BitstringStatusListCredentialFactoryTest {

    private final BitstringStatusListCredentialFactory factory = new BitstringStatusListCredentialFactory();

    @Test
    void buildUnsigned_shouldBuildExpectedCredentialStructure() {
        // Arrange
        String listUrl = "https://example.com/status/123";
        String issuerId = "did:example:issuer";
        String purpose = "revocation";
        String encodedList = "H4sIAAAAA...";

        // Act
        Map<String, Object> vc = factory.buildUnsigned(listUrl, issuerId, purpose, encodedList);

        // Assert: top-level
        assertThat(vc)
                .containsKeys("@context", "id", "type", "issuer", "credentialSubject")
                .containsEntry("id", listUrl)
                .containsEntry("issuer", issuerId);

        // Assert: @context (Object[])
        Object[] context = (Object[]) vc.get("@context");
        assertThat(context).containsExactly(
                "https://www.w3.org/ns/credentials/v2",
                "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld"
        );

        // Assert: type (Object[])
        Object[] types = (Object[]) vc.get("type");
        assertThat(types).containsExactly(VC_TYPE, STATUS_LIST_CREDENTIAL_TYPE);

        // Assert: credentialSubject (ENCADENAT)
        @SuppressWarnings("unchecked")
        Map<String, Object> subject = (Map<String, Object>) vc.get("credentialSubject");

        assertThat(subject)
                .containsEntry("type", STATUS_LIST_SUBJECT_TYPE)
                .containsEntry("statusPurpose", purpose)
                .containsEntry("encodedList", encodedList);
    }


    @Test
    void buildUnsigned_shouldPreserveInsertionOrder() {
        // Arrange
        String listUrl = "https://example.com/status/123";
        String issuerId = "did:example:issuer";
        String purpose = "revocation";
        String encodedList = "abc";

        // Act
        Map<String, Object> vc = factory.buildUnsigned(listUrl, issuerId, purpose, encodedList);

        // Assert: LinkedHashMap insertion order (as built in the factory)
        List<String> keys = new ArrayList<>(vc.keySet());
        assertThat(keys).containsExactly("@context", "id", "type", "issuer", "credentialSubject");

        @SuppressWarnings("unchecked")
        Map<String, Object> subject = (Map<String, Object>) vc.get("credentialSubject");
        List<String> subjectKeys = new ArrayList<>(subject.keySet());
        assertThat(subjectKeys).containsExactly("type", "statusPurpose", "encodedList");
    }

    @Test
    void buildUnsigned_shouldThrowWhenAnyParamIsNull() {
        // Arrange
        String listUrl = "https://example.com/status/123";
        String issuerId = "did:example:issuer";
        String purpose = "revocation";
        String encodedList = "abc";

        // Act + Assert
        assertThrows(RuntimeException.class, () -> factory.buildUnsigned(null, issuerId, purpose, encodedList));
        assertThrows(RuntimeException.class, () -> factory.buildUnsigned(listUrl, null, purpose, encodedList));
        assertThrows(RuntimeException.class, () -> factory.buildUnsigned(listUrl, issuerId, null, encodedList));
        assertThrows(RuntimeException.class, () -> factory.buildUnsigned(listUrl, issuerId, purpose, null));
    }

    @Test
    void buildStatusListEntry_shouldBuildExpectedEntry() {
        // Arrange
        String listUrl = "https://example.com/status/123";
        Integer idx = 7;
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        // Act
        StatusListEntry entry = factory.buildStatusListEntry(listUrl, idx, purpose);

        // Assert
        assertThat(entry)
                .returns(listUrl + "#" + idx, StatusListEntry::id)
                .returns(BITSTRING_ENTRY_TYPE, StatusListEntry::type)
                .returns(purpose, StatusListEntry::statusPurpose)
                .returns(String.valueOf(idx), StatusListEntry::statusListIndex)
                .returns(listUrl, StatusListEntry::statusListCredential);
    }

    @Test
    void buildStatusListEntry_shouldThrowWhenAnyParamIsNull() {
        // Arrange
        String listUrl = "https://example.com/status/123";
        Integer idx = 7;
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        // Act + Assert
        assertThrows(RuntimeException.class, () -> factory.buildStatusListEntry(null, idx, purpose));
        assertThrows(RuntimeException.class, () -> factory.buildStatusListEntry(listUrl, null, purpose));
        assertThrows(RuntimeException.class, () -> factory.buildStatusListEntry(listUrl, idx, null));
    }
}

