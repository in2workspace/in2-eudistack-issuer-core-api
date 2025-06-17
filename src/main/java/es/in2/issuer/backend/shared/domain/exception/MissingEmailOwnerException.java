package es.in2.issuer.backend.shared.domain.exception;

public class MissingEmailOwnerException extends RuntimeException {
    public MissingEmailOwnerException(String message) {
        super(message);
    }
}
