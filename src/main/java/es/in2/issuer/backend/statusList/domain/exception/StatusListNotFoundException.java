package es.in2.issuer.backend.statusList.domain.exception;

public class StatusListNotFoundException extends RuntimeException {

    private final Long listId;

    public StatusListNotFoundException(Long listId) {
        super("Status list not found");
        this.listId = listId;
    }

    public Long getListId() {
        return listId;
    }
}

