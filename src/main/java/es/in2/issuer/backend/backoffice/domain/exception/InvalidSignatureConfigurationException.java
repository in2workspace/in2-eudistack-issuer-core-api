package es.in2.issuer.backend.backoffice.domain.exception;

public class InvalidSignatureConfigurationException extends RuntimeException {
    public InvalidSignatureConfigurationException(String message) {
        super(message);
    }
}
