package es.in2.issuer.backend.shared.domain.util;

public class EndpointsConstants {

    private EndpointsConstants() {
        throw new IllegalStateException("Utility class");
    }

    // Management Endpoints
    public static final String SWAGGER_UI_PATH = "/swagger-ui/**";
    public static final String SWAGGER_RESOURCES_PATH = "/swagger-resources/**";
    public static final String SWAGGER_API_DOCS_PATH = "/api-docs/**";
    public static final String SWAGGER_SPRING_UI_PATH = "/spring-ui/**";
    public static final String SWAGGER_WEBJARS_PATH = "/webjars/swagger-ui/**";
    public static final String HEALTH_PATH = "/health";
    public static final String PROMETHEUS_PATH = "/prometheus";

    // VCI API Endpoints
    public static final String VCI_ISSUANCES_PATH = "/vci/v1/issuances";

    // OIDC4VCI Endpoints
    public static final String OID4VCI_CREDENTIAL_OFFER_PATH = "/oid4vci/v1/credential-offer";
    public static final String OID4VCI_CREDENTIAL_PATH = "/oid4vci/v1/credential";
    public static final String OID4VCI_DEFERRED_CREDENTIAL_PATH = "/oid4vci/v1/deferred-credential";

    // Well-Known Endpoints
    public static final String CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH = "/.well-known/openid-credential-issuer";
    public static final String AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH = "/.well-known/openid-configuration";

    // OIDC Endpoints
    public static final String OAUTH_TOKEN_PATH = "/oauth/token";

    // CORS Configuration
    public static final String CORS_OID4VCI_PATH = "/oid4vci/**";
    public static final String CORS_CREDENTIAL_OFFER_PATH = "/oid4vci/v1/credential-offer/**"; // TODO: revisar si debe ser con {id}
    public static final String STATUS_CREDENTIALS = "/backoffice/v1/credentials/status/**";

    // todo: remove these constants if not needed
    public static final String TRUST_FRAMEWORK_ISSUER = "/issuer";
    public static final String DEFERRED_CREDENTIALS = "/api/v1/deferred-credentials";


}
