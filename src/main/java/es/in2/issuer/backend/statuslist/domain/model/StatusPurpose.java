package es.in2.issuer.backend.statuslist.domain.model;

import java.util.Locale;

/**
 * W3C Status Purpose.
 * Currently only REVOCATION is in scope.
 */
public enum StatusPurpose {
    REVOCATION("revocation");

    private final String value;

    StatusPurpose(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static StatusPurpose fromValue(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("statusPurpose");
        }
        String normalized = raw.trim().toLowerCase(Locale.ROOT);
        for (StatusPurpose p : values()) {
            if (p.value.equals(normalized)) {
                return p;
            }
        }
        throw new IllegalArgumentException("Unsupported statusPurpose: " + raw);
    }
}

