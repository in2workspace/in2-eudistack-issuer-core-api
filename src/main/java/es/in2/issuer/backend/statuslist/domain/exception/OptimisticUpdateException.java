package es.in2.issuer.backend.statuslist.domain.exception;

public class OptimisticUpdateException extends RuntimeException {
    public OptimisticUpdateException(String message) {
        super(message);
    }
}
