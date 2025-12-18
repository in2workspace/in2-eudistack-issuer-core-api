package es.in2.issuer.backend.shared.domain.exception;

public class CredentialProcedureNotFoundException extends RuntimeException {
    public CredentialProcedureNotFoundException(String message) {
        super(message);
    }
}
