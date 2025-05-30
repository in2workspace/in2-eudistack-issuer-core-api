package es.in2.issuer.backend.backoffice.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.Map;

@Builder
public record SubjectDataResponse(
        @JsonProperty("credentialSubjectData") Map<String, Map<String, String>> credentialSubjectData) {
}
