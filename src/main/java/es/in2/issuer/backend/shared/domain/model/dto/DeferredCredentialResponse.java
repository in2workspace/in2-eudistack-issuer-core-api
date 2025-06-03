package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

import java.util.List;

@Builder
@Schema(description = """
        Implements the credential response according to 
        https://github.com/hesusruiz/EUDIMVP/blob/main/issuance.md#credential-response
        """)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeferredCredentialResponse(
        @Schema(example = "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L", description = "Contains issued Credential") @JsonProperty(value = "credentials", required = true) List<String> credentials) {
}
