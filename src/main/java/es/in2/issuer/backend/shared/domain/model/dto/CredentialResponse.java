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
public record CredentialResponse(
        @Schema(example = "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L", description = "Contains issued Credential") @JsonProperty(value = "credentials") List<Credential> credentials,
        @Schema(example = "958e84cf-888b-488a-bf30-7f3b14f70699", description = "Transaction id for deferred emission") @JsonProperty("transaction_id") String transactionId,
        @Schema(example = "urn:uuid:3fa85f64-5717-4562-b3fc-2c963f66afa6",description = "Identifier used by the Wallet to notify credential lifecycle events") @JsonProperty("notification_id") String notificationId) {

    @Builder
    public record Credential(@JsonProperty String credential) {

    }
}
