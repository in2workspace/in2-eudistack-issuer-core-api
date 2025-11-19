package es.in2.issuer.backend.shared.domain.exception;

public class CredentialProcedureInvalidStatusException extends RuntimeException {
    public CredentialProcedureInvalidStatusException(String message) {
        super(message);
    }
}
