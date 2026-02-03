package es.in2.issuer.backend.statuslist.domain.util;

public class Constants {

    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String BITSTRING_ENTRY_TYPE = "BitstringStatusListEntry";
    public static final String STATUS_LIST_CREDENTIAL_TYPE = "BitstringStatusListCredential";
    public static final String STATUS_LIST_SUBJECT_TYPE = "BitstringStatusList";
    public static final String VC_TYPE = "VerifiableCredential";
    public static final int CAPACITY_BITS = 131_072; // 16KB * 8
    public static final String TOKEN = "token";
    public static final double NEW_LIST_THRESHOLD = 0.80;
    public static final String REVOKED = "REVOKED";
}
