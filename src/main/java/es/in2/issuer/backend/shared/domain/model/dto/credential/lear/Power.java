package es.in2.issuer.backend.shared.domain.model.dto.credential.lear;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record Power(
        @JsonProperty("action") @JsonAlias("tmf_action") Object action,
        @JsonProperty("domain") @JsonAlias("tmf_domain") String domain,
        @JsonProperty("function") @JsonAlias("tmf_function") String function,
        @JsonProperty("type") @JsonAlias("tmf_type") String type
) { }