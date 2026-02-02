package es.in2.issuer.backend.statuslist.domain.exception;

public class ConcurrentStatusListUpdateException extends RuntimeException {

    private final Long statusListId;
    private final Integer idx;

    public ConcurrentStatusListUpdateException(Long statusListId, Integer idx, Throwable cause) {
        super("Concurrent update while revoking status list");
        this.statusListId = statusListId;
        this.idx = idx;
        initCause(cause);
    }

    public Long getStatusListId() {
        return statusListId;
    }

    public Integer getIdx() {
        return idx;
    }
}

