package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import lombok.Builder;

@Builder
public record LEARCredentialEmployeeJwtPayload(
        @JsonProperty("sub")
        String subject,

        @JsonProperty("nbf")
        Long notValidBefore,

        @JsonProperty("iss")
        String issuer,

        @JsonProperty("exp")
        Long expirationTime,

        @JsonProperty("iat")
        Long issuedAt,

        @JsonProperty("vc")
        LEARCredentialEmployee learCredentialEmployee,

        @JsonProperty("jti")
        String JwtId,

        @JsonProperty("cnf")
        Object cnf
) {
}
