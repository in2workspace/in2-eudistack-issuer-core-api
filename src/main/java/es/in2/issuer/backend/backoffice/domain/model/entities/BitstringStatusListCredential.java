package es.in2.issuer.backend.backoffice.domain.model.entities;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;
import java.util.List;

//todo fer dto?
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BitstringStatusListCredential {

    private int id;
    private List<String> type;
    private String issuer;
    private OffsetDateTime validFrom;
    private OffsetDateTime validUntil;
    private CredentialSubject credentialSubject;

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class CredentialSubject {

        private String id;
        private String type; // must be "BitstringStatusList"
        private String statusPurpose; // currently it must be "revocation"
        private String encodedList; // Multibase base64url of GZIP-compressed bitstring
    }
}

