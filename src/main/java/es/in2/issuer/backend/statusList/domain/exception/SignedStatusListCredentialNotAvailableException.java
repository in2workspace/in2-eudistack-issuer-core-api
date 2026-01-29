package es.in2.issuer.backend.statusList.domain.exception;

public class SignedStatusListCredentialNotAvailableException extends RuntimeException {

    private final Long listId;

    public SignedStatusListCredentialNotAvailableException(Long listId) {
        super("Signed status list credential not available");
        this.listId = listId;
    }

    public Long getListId() {
        return listId;
    }
}

