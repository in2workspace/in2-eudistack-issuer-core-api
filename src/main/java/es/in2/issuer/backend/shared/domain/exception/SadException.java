package es.in2.issuer.backend.shared.domain.exception;

import java.io.Serial;

public class SadException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    public SadException(String message) {
        super(message);
    }
}
