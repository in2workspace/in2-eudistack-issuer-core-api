package es.in2.issuer.backend.shared.domain.model.dto.credential;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Builder;
import org.jetbrains.annotations.NotNull;

import java.util.List;

@Builder
public record LabelCredential(
        @JsonProperty("@context") List<String> context,
        @JsonProperty("id") String id,
        @NotNull
        @JsonProperty("type") List<String> type,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class) Issuer issuer,
        @NotNull
        @JsonProperty("credentialSubject") CredentialSubject credentialSubject,
        @NotNull
        @JsonProperty("validFrom") String validFrom,
        @NotNull
        @JsonProperty("validUntil") String validUntil,
        @JsonProperty("credentialStatus") CredentialStatus credentialStatus) {
    @Builder
    public record CredentialSubject(
            @JsonProperty("id") String id,
            @JsonProperty("gx:labelLevel") String gxLabelLevel,
            @JsonProperty("gx:engineVersion") String gxEngineVersion,
            @JsonProperty("gx:rulesVersion") String gxRulesVersion,
            @JsonProperty("gx:compliantCredentials") List<CompliantCredentials> gxCompliantCredentials,
            @JsonProperty("gx:validatedCriteria") List<String> gxValidatedCriteria
    ) {
        @Builder
        public record CompliantCredentials(
                @JsonProperty("id") String id,
                @JsonProperty("type") String type,
                @JsonProperty("gx:digestSRI") String gxDigestSRI
        ) {
        }
    }
}
