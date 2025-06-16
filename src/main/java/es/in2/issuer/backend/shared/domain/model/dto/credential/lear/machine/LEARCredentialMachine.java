package es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatusObject;
import es.in2.issuer.backend.shared.domain.model.dto.credential.Issuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.IssuerDeserializer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.*;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record LEARCredentialMachine(
        @JsonProperty("@context") List<String> context,
        @JsonProperty("id") String id,
        @JsonProperty("type") List<String> type,
        @JsonProperty("description") String description,
        @JsonProperty("credentialSubject") CredentialSubject credentialSubject,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class) Issuer issuer,
        @JsonProperty("validFrom") String validFrom,
        @JsonProperty("validUntil") String validUntil,
        @JsonProperty("credentialStatus") CredentialStatusObject credentialStatus
) implements LEARCredential {

    @Builder
    public record CredentialSubject(
            @JsonProperty("mandate") Mandate mandate
    ) {
        @Builder
        public record Mandate(
                @JsonProperty("id") String id,
                @JsonProperty("life_span") LifeSpan lifeSpan,
                @JsonProperty("mandatee") Mandatee mandatee,
                @JsonProperty("mandator") Mandator mandator,
                @JsonProperty("power") List<Power> power,
                @JsonProperty("signer") Signer signer
                ) {
            @Builder
            public record Mandatee(
                    @JsonProperty("id") String id,
                    @JsonProperty("serviceName") String serviceName,
                    @JsonProperty("serviceType") String serviceType,
                    @JsonProperty("version") String version,
                    @JsonProperty("domain") String domain,
                    @JsonProperty("ipAddress") String ipAddress,
                    @JsonProperty("description") String description,
                    @JsonProperty("contact") Contact contact
            ) {
                @Builder
                public record Contact(
                        @JsonProperty("email") String email,
                        @JsonProperty("phone") String mobilePhone
                ) {}
            }
        }
    }
}
