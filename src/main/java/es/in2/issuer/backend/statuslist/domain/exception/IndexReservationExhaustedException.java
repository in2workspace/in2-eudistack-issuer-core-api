package es.in2.issuer.backend.statuslist.domain.exception;

public class IndexReservationExhaustedException extends RuntimeException {
    public IndexReservationExhaustedException(String message, Throwable cause) {
        super(message, cause);
    }
}