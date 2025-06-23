package es.in2.issuer.backend.shared.domain.util;

import java.util.List;

public final class Constants {
    public static final String LEAR_CREDENTIAL = "LEARCredential";
    public static final String JWT_VC_JSON = "jwt_vc_json";
    public static final String VERIFIABLE_CREDENTIAL = "VerifiableCredential";
    public static final String LEAR_CREDENTIAL_EMPLOYEE = "LEARCredentialEmployee";
    public static final String LEAR_CREDENTIAL_MACHINE = "LEARCredentialMachine";
    public static final String VERIFIABLE_CERTIFICATION = "VerifiableCertification";
    public static final List<String> VERIFIABLE_CERTIFICATION_TYPE = List.of(VERIFIABLE_CERTIFICATION, VERIFIABLE_CREDENTIAL);
    public static final String VERIFIABLE_CERTIFICATION_CREDENTIAL_TYPE = "VERIFIABLE_CERTIFICATION";
    public static final String LEAR_CREDENTIAL_EMPLOYEE_CREDENTIAL_TYPE = "LEAR_CREDENTIAL_EMPLOYEE";

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    public static final List<String> CREDENTIAL_CONTEXT_LEAR_CREDENTIAL_EMPLOYEE = List.of("https://www.w3.org/ns/credentials/v2", "https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2");
    public static final List<String> CREDENTIAL_CONTEXT_LEAR_CREDENTIAL_MACHINE = List.of("https://www.w3.org/ns/credentials/v2", "https://www.dome-marketplace.eu/2025/credentials/learcredentialmachine/v2");
    // EXPIRATION TIMES
    public static final Integer CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME = 10;
    public static final Integer VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME = 10;
    public static final Integer CLIENT_ASSERTION_EXPIRATION_TIME = 2;
    public static final String CLIENT_ASSERTION_EXPIRATION_TIME_UNIT = "MINUTES";

    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final long PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES = 5;
    public static final String ENGLISH = "en";
    public static final String DEFAULT_USER_NAME = "Cloud Provider";
    public static final String LEAR_CREDENTIAL_MACHINE_DESCRIPTION = "Verifiable Credential for machines";
}
