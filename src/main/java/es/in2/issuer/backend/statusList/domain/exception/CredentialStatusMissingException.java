package es.in2.issuer.backend.statusList.domain.exception;

public class CredentialStatusMissingException extends RuntimeException {

    private final String procedureId;

    public CredentialStatusMissingException(String procedureId) {
        super("credentialStatus not found in credentialDecoded");
        this.procedureId = procedureId;
    }

    public CredentialStatusMissingException(String procedureId, Throwable cause) {
        super("credentialStatus not found in credentialDecoded", cause);
        this.procedureId = procedureId;
    }

    public String getProcedureId() {
        return procedureId;
    }
}