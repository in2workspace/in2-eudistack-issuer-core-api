package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when there is no status_list_index mapping for a given credential procedure.
 */
public class StatusListIndexNotFoundException extends RuntimeException {

    private final String procedureId;

    public StatusListIndexNotFoundException(String procedureId) {
        super("Status list index not found for credential procedure");
        this.procedureId = procedureId;
    }

    public String getProcedureId() {
        return procedureId;
    }
}

