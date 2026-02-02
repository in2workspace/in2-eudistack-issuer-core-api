package es.in2.issuer.backend.statuslist.domain.exception;

public class StatusListSigningPersistenceException extends RuntimeException {

    private final Long statusListId;

    public StatusListSigningPersistenceException(Long statusListId) {
        super("Failed to persist signed status list credential");
        this.statusListId = statusListId;
    }

    public Long getStatusListId() {
        return statusListId;
    }
}
