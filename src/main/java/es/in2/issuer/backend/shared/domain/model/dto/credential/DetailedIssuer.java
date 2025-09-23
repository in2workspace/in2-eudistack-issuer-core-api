package es.in2.issuer.backend.shared.domain.model.dto.credential;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;


@Builder
public record DetailedIssuer(
        @JsonProperty("id") String id,
        @JsonProperty("organizationIdentifier") String organizationIdentifier,
        @JsonProperty("organization") String organization,
        @JsonProperty("country") String country,
        @JsonProperty("commonName") String commonName,
        @JsonProperty("serialNumber") String serialNumber
) implements Issuer {
    @Override
    public String getId() {
        return id;
    }
}

