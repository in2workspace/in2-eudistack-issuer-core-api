package es.in2.issuer.backend.backoffice.domain.model.dtos;

public record RevokeCredentialRequest(String credentialId, int listId) {
}
