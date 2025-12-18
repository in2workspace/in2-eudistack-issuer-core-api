package es.in2.issuer.backend.shared.domain.util;

public class EndpointsConstants {

    private EndpointsConstants() {
        throw new IllegalStateException("Utility class");
    }

    // Management Endpoints
    public static final String HEALTH_PATH = "/health";
    public static final String PROMETHEUS_PATH = "/prometheus";
    public static final String SPRINGDOC_BASE_PATH = "/springdoc";
    public static final String SPRINGDOC_PATH = SPRINGDOC_BASE_PATH+"/**";
    public static final String BACKOFFICE_BASE_PATH = "/backoffice/v1";
    public static final String OID4VCI_BASE_PATH = "/oid4vci/v1";
    public static final String WELL_KNOWN_BASE_PATH ="/.well-known";
    public static final String VCI_BASE_PATH = "/vci/v1";

    // VCI API Endpoints
    public static final String VCI_PATH = VCI_BASE_PATH+"/**";
    public static final String VCI_ISSUANCES_PATH = VCI_BASE_PATH+"/issuances";

    // OIDC4VCI Endpoints
    public static final String CORS_OID4VCI_PATH = "/oid4vci/**";
    public static final String OID4VCI_CREDENTIAL_OFFER_PATH = OID4VCI_BASE_PATH + "/credential-offer";
    public static final String OID4VCI_CREDENTIAL_PATH = OID4VCI_BASE_PATH + "/credential";
    public static final String OID4VCI_DEFERRED_CREDENTIAL_PATH = OID4VCI_BASE_PATH + "/deferred-credential";

    public static final String CORS_CREDENTIAL_OFFER_PATH = OID4VCI_BASE_PATH + "/credential-offer/**";

    // Well-Known Endpoints
    public static final String WELL_KNOWN_PATH = WELL_KNOWN_BASE_PATH + "/**";
    public static final String CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH = WELL_KNOWN_BASE_PATH + "/openid-credential-issuer";
    public static final String AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH = WELL_KNOWN_BASE_PATH + "/openid-configuration";

    // oauth Endpoints
    public static final String OAUTH_PATH ="/oauth/**";
    public static final String OAUTH_TOKEN_PATH = "/oauth/token";

    //backoffice Endpoints
    public static final String BACKOFFICE_PATH = "/backoffice/**";
    public static final String BACKOFFICE_STATUS_CREDENTIALS = BACKOFFICE_BASE_PATH+"/credentials/status/**";
    public static final String BACKOFFICE_RETRY_SIGN_CREDENTIALS = BACKOFFICE_BASE_PATH+"/retry-sign-credential/{id}";
    public static final String BACKOFFICE_DEFERRED_CREDENTIALS = BACKOFFICE_BASE_PATH + "/deferred-credentials";
    public static final String BACKOFFICE_ISSUANCE = BACKOFFICE_BASE_PATH+"/issuances";

    // todo: remove these constants if not needed
    public static final String TRUST_FRAMEWORK_ISSUER = "/issuer";



}
