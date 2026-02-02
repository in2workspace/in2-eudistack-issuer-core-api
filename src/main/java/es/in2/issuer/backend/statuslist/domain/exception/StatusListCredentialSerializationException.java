package es.in2.issuer.backend.statuslist.domain.exception;

public class StatusListCredentialSerializationException extends RuntimeException {

    public StatusListCredentialSerializationException(Throwable cause) {
        super("Failed to serialize status list credential payload");
        initCause(cause);
    }
}

