package es.in2.issuer.backend.backoffice.domain.model.dtos;

import java.util.Map;

/**
 * Simple DTO capturing only fields that changed.
 */
public record ChangeSet(
        Map<String,Object> oldValues,
        Map<String,Object> newValues
) {}
