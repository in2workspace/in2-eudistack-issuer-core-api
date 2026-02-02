package es.in2.issuer.backend.statuslist.domain.exception;

public class StatusListIndexMissingException extends RuntimeException {

    private final Long statusListId;

    public StatusListIndexMissingException(Long statusListId) {
        super("Status list index is missing for statusListId=" + statusListId);
        this.statusListId = statusListId;
    }

    public Long getStatusListId() {
        return statusListId;
    }
}