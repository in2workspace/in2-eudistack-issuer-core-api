package es.in2.issuer.backend.shared.domain.exception;

public class InvalidTokenException extends Exception {

    private static final String DEFAULT_MESSAGE = "The request contains the wrong Access Token or the Access Token is missing";

    public InvalidTokenException() {
        super(DEFAULT_MESSAGE);
    }

    public InvalidTokenException(String message) {
        super((message == null || message.trim().isEmpty()) ? DEFAULT_MESSAGE : message);
    }


}
