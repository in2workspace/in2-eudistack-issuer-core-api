package es.in2.issuer.backend.backoffice.domain.model.dtos;

import lombok.Builder;

@Builder
public record VcTemplate(Boolean mutable, String name, String template) {
}
