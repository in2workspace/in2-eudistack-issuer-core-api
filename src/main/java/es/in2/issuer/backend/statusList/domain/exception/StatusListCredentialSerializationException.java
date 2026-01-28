package es.in2.issuer.backend.statusList.domain.exception;

public class StatusListCredentialSerializationException extends RuntimeException {

    public StatusListCredentialSerializationException(Throwable cause) {
        super("Failed to serialize status list credential payload");
        initCause(cause);
    }
}

