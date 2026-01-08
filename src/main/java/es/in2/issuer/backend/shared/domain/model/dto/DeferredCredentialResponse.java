package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeferredCredentialResponse(
        @JsonProperty(value = "credentials", required = true) List<Credential> credentials) {

    @Builder
    public record Credential(@JsonProperty String credential) {
    }
}
