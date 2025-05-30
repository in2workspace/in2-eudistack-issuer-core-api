package es.in2.issuer.backend.backoffice.domain.exception;

public class OrganizationIdentifierMismatchException extends RuntimeException {
    public OrganizationIdentifierMismatchException(String message) {
        super(message);
    }
}
