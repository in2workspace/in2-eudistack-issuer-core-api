package es.in2.issuer.backend.shared.domain.exception;

public class FormatUnsupportedException extends RuntimeException {
    public FormatUnsupportedException(String message) {
        super(message);
    }

}