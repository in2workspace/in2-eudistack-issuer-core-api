package es.in2.issuer.backend.statuslist.domain.util;

import static java.util.Objects.requireNonNull;

public final class Preconditions {

    private static final String CANNOT_BE_NULL = " cannot be null";

    private Preconditions() {
        throw new IllegalStateException("Utility class");
    }

    public static <T> T requireNonNullParam(T value, String name) {
        return requireNonNull(value, name + CANNOT_BE_NULL);
    }
}
