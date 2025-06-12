package es.in2.issuer.backend.shared.domain.model.dto;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

@Builder
@Schema(description = """
    Implements the credential response according to 
    https://github.com/hesusruiz/EUDIMVP/blob/main/issuance.md#credential-response
    """)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record VerifiableCredentialResponse(
        //@Schema(example = "jwt_vc_json", description = "Format of the issued Credential.") @JsonProperty("format") String format,
        @Schema(example = "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L", description = "Contains issued Credential") @JsonProperty("credential") String credential,
        @Schema(example = "958e84cf-888b-488a-bf30-7f3b14f70699", description = "Transaction id for deferred emission") @JsonProperty("transaction_id") String transactionId,
        @Schema(example = "fGFF7UkhLA",
                description = """
            Nonce to be used to create a proof of possession of key material when requesting a Credential. 
            When received, the Wallet MUST use this nonce value for its subsequent credential requests until the 
            Credential Issuer provides a fresh nonce.
                                                    """) @JsonProperty("c_nonce") String cNonce,
        @Schema(example = "35fd", description = "Lifetime in seconds of the c_nonce") @JsonProperty("c_nonce_expires_in") int cNonceExpiresIn) {
}
