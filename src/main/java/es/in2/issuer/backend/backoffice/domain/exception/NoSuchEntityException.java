package es.in2.issuer.backend.backoffice.domain.exception;

public class NoSuchEntityException extends RuntimeException {
    public NoSuchEntityException(String message) {
        super(message);
    }
}
