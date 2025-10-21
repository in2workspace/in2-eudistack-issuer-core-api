package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record Grants(
        @JsonProperty("pre-authorized_code") String preAuthorizedCode,
        @JsonProperty("tx_code") TxCode txCode
) {

    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record TxCode(
            @JsonProperty("length") int length,
            @JsonProperty("input_mode") String inputMode,
            //todo consider removing this field
            @JsonProperty("description") String description
    ) {
    }
}
