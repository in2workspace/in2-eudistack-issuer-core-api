package es.in2.issuer.backend.statuslist.domain.factory;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.*;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@Slf4j
@RequiredArgsConstructor
@Component
public class BitstringStatusListCredentialFactory {

    public Map<String, Object> buildUnsigned(String listUrl, String issuerId, String purpose, String encodedList) {
        return buildCredential(listUrl, issuerId, purpose, encodedList);
    }

    public StatusListEntry buildStatusListEntry(String listUrl, Integer idx, StatusPurpose purpose) {
        log.debug("Building status list entry - idx: {}", idx);
        requireNonNullParam(listUrl, "listUrl");
        requireNonNullParam(idx, "idx");
        requireNonNullParam(purpose, "purpose");

        String id = listUrl + "#" + idx;

        return StatusListEntry.builder()
                .id(id)
                .type(BITSTRING_ENTRY_TYPE)
                .statusPurpose(purpose)
                .statusListIndex(String.valueOf(idx))
                .statusListCredential(listUrl)
                .build();
    }

    private Map<String, Object> buildCredential(String listUrl, String issuerId, String purpose, String encodedList) {
        requireNonNullParam(listUrl, "listUrl");
        requireNonNullParam(issuerId, "issuerId");
        requireNonNullParam(purpose, "purpose");
        requireNonNullParam(encodedList, "encodedList");

        Map<String, Object> credentialSubject = new LinkedHashMap<>();
        credentialSubject.put("type", STATUS_LIST_SUBJECT_TYPE);
        credentialSubject.put("statusPurpose", purpose);
        credentialSubject.put("encodedList", encodedList);

        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("@context", new Object[]{
                "https://www.w3.org/ns/credentials/v2",
                "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld"
        });
        vc.put("id", listUrl);
        vc.put("type", new Object[]{VC_TYPE, STATUS_LIST_CREDENTIAL_TYPE});
        vc.put("issuer", issuerId);
        vc.put("credentialSubject", credentialSubject);

        return vc;
    }
}
