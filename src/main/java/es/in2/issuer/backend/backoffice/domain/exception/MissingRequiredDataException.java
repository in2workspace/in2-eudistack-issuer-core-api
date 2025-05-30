package es.in2.issuer.backend.backoffice.domain.exception;

public class MissingRequiredDataException extends RuntimeException {
    public MissingRequiredDataException(String message) {
        super(message);
    }
}
