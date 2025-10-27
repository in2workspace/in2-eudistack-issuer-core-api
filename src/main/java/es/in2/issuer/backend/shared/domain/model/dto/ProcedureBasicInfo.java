package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

@Builder
public record ProcedureBasicInfo(
        @JsonProperty("procedure_id") UUID procedureId,
        @JsonProperty("subject") String subject,
        @JsonProperty("credential_type") String credentialType,
        @JsonProperty("status") String status,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
        @JsonProperty("updated") Instant updated,
        @JsonProperty("organization_identifier") String organizationIdentifier
) {
}
