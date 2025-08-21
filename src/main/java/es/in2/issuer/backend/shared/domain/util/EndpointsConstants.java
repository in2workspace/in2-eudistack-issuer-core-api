package es.in2.issuer.backend.shared.domain.util;

public class EndpointsConstants {

    private EndpointsConstants() {
        throw new IllegalStateException("Utility class");
    }

    // Management Endpoints
    public static final String ACTUATOR_BASE_PATH =  "/actuator";
    public static final String SPRINGDOC_BASE_PATH = "/springdoc";
    public static final String BACKOFFICE_BASE_PATH = "/backoffice";

    // VCI API Endpoints
    public static final String VCI_PATH = "/vci/v1/**";
    public static final String VCI_ISSUANCES_PATH = "/vci/v1/issuances";

    // OIDC4VCI Endpoints
    public static final String OID4VCI_CREDENTIAL_OFFER_PATH = "/oid4vci/v1/credential-offer";
    public static final String OID4VCI_CREDENTIAL_PATH = "/oid4vci/v1/credential";
    public static final String OID4VCI_DEFERRED_CREDENTIAL_PATH = "/oid4vci/v1/deferred-credential";

    // Well-Known Endpoints
    public static final String WELL_KNOWN_PATH ="/.well-known/**";
    public static final String CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH = "/.well-known/openid-credential-issuer";
    public static final String AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH = "/.well-known/openid-configuration";

    // OIDC Endpoints
    public static final String OAUTH_PATH ="/oauth/**";
    public static final String OAUTH_TOKEN_PATH = "/oauth/token";

    // CORS Configuration
    public static final String CORS_OID4VCI_PATH = "/oid4vci/**";
    public static final String CORS_CREDENTIAL_OFFER_PATH = "/oid4vci/v1/credential-offer/**"; //TODO: en lugar de ** debería ser {id} para especificar?
    public static final String STATUS_CREDENTIALS = "/backoffice/v1/credentials/status/**";

    // todo: remove these constants if not needed
    public static final String TRUST_FRAMEWORK_ISSUER = "/issuer";
    public static final String DEFERRED_CREDENTIALS = "/backoffice/v1/deferred-credentials";


}
