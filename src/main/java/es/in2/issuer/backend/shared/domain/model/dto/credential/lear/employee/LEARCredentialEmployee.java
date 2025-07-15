package es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.Issuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.IssuerDeserializer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.*;
import lombok.Builder;

import java.util.List;

@Builder
public record LEARCredentialEmployee(
        @JsonProperty("@context") List<String> context,
        @JsonProperty("id") String id,
        @JsonProperty("type") List<String> type,
        @JsonProperty("description") String description,
        @JsonProperty("credentialSubject") CredentialSubject credentialSubject,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class) Issuer issuer,
        @JsonProperty("validFrom") String validFrom,
        @JsonProperty("validUntil") String validUntil,
        @JsonProperty("credentialStatus") CredentialStatus credentialStatus
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
                    @JsonProperty("email") String email,
                    // To keep compatibility with the v1 credential we keep the old name
                    @JsonProperty("firstName") @JsonAlias("first_name") String firstName,
                    // To keep compatibility with the v1 credential we keep the old name
                    @JsonProperty("lastName") @JsonAlias("last_name") String lastName,
                    @JsonProperty("mobile_phone") String mobilePhone,
                    @JsonProperty("nationality") String nationality
            ) { }
        }
    }
}


