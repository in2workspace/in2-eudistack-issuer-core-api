package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when credentialDecoded cannot be parsed as JSON.
 */
public class CredentialDecodedInvalidJsonException extends RuntimeException {

    private final String procedureId;

    public CredentialDecodedInvalidJsonException(String procedureId, Throwable cause) {
        super("credentialDecoded is not valid JSON");
        this.procedureId = procedureId;
        initCause(cause);
    }

    public String getProcedureId() {
        return procedureId;
    }
}
