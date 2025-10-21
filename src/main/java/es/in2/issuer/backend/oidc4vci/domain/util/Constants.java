package es.in2.issuer.backend.oidc4vci.domain.util;

public final class Constants {

    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final int TX_CODE_SIZE = 4;
    public static final String TX_INPUT_MODE = "numeric";
    public static final long ACCESS_TOKEN_EXPIRATION_TIME_DAYS = 30L;
}
