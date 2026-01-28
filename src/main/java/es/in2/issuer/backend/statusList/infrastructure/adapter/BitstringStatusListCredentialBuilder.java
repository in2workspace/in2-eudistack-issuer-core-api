package es.in2.issuer.backend.statusList.infrastructure.adapter;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.statusList.domain.model.StatusListEntry;
import es.in2.issuer.backend.statusList.domain.model.StatusPurpose;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

import static es.in2.issuer.backend.statusList.domain.util.Constants.*;
import static java.util.Objects.requireNonNull;

@Slf4j
@RequiredArgsConstructor
@Component
public class BitstringStatusListCredentialBuilder {

    private final AppConfig appConfig;

    public String buildListUrl(Long listId) {
        requireNonNull(listId, "listId cannot be null");
        return appConfig.getIssuerBackendUrl() + "/api/v1/status-list" + "/" + listId;
    }

    public Map<String, Object> buildUnsigned(Long listId, String issuerId, String purpose, String encodedList) {
        return buildCredential(listId, issuerId, purpose, encodedList);
    }

    public StatusListEntry buildStatusListEntry(Long listId, Integer idx, StatusPurpose purpose) {
        log.debug("Building status list entry - listId: {}, idx: {}", listId, idx);

        requireNonNull(listId, "listId cannot be null");
        requireNonNull(idx, "idx cannot be null");
        requireNonNull(purpose, "purpose cannot be null");

        String listUrl = buildListUrl(listId);
        String id = listUrl + "#" + idx;

        return StatusListEntry.builder()
                .id(id)
                .type(BITSTRING_ENTRY_TYPE)
                .statusPurpose(purpose)
                .statusListIndex(String.valueOf(idx))
                .statusListCredential(listUrl)
                .build();
    }

    private Map<String, Object> buildCredential(Long listId, String issuerId, String purpose, String encodedList) {
        requireNonNull(listId, "listId cannot be null");
        requireNonNull(issuerId, "issuerId cannot be null");
        requireNonNull(purpose, "purpose cannot be null");
        requireNonNull(encodedList, "encodedList cannot be null");

        String listUrl = buildListUrl(listId);

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
