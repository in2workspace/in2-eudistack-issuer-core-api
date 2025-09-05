package es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.Issuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.IssuerDeserializer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LEARCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record LEARCredentialMachine(
        @JsonProperty("@context") List<String> context,
        @JsonProperty("id") String id,
        @JsonProperty("type") List<String> type,
        @JsonProperty("name") String name,
        @JsonProperty("description") String description,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class) Issuer issuer,
        @JsonProperty("validFrom") String validFrom,
        @JsonProperty("validUntil") String validUntil,
        @JsonProperty("credentialSubject") CredentialSubject credentialSubject,
        @JsonProperty("credentialStatus") CredentialStatus credentialStatus

) implements LEARCredential {

    @Builder
    public record CredentialSubject(
            @JsonProperty("mandate") Mandate mandate
    ) {
        @Builder
        public record Mandate(
                @JsonProperty("id") String id,
                @JsonProperty("mandator") Mandator mandator,
                @JsonProperty("mandatee") Mandatee mandatee,
                @JsonProperty("power") List<Power> power
        ) {
            @Builder
            public record Mandator(
                    @JsonProperty("id") String id,
                    @JsonProperty("organization") String organization,
                    @JsonProperty("organizationIdentifier") String organizationIdentifier,
                    @JsonProperty("country") String country,
                    @JsonProperty("commonName") String commonName,
                    @JsonProperty("serialNumber") String serialNumber,
                    @JsonProperty("email") String email
            ) {
            }

            @Builder
            public record Mandatee(
                    @JsonProperty("id") String id,
                    @JsonProperty("domain") String domain,
                    @JsonProperty("ipAddress") String ipAddress
            ) {
            }
        }
    }
}
