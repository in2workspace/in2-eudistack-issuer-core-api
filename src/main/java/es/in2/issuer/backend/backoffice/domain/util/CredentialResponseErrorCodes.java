package es.in2.issuer.backend.backoffice.domain.util;

public class CredentialResponseErrorCodes {

    private CredentialResponseErrorCodes() {
        throw new IllegalStateException("Utility class");
    }

    public static final String INVALID_TOKEN = "invalid_token";
    public static final String UNSUPPORTED_CREDENTIAL_TYPE = "unsupported_credential_type";
    public static final String INVALID_OR_MISSING_PROOF = "invalid_or_missing_proof";
    public static final String EXPIRED_PRE_AUTHORIZED_CODE = "pre-authorized_code is expired or used";
    public static final String VC_TEMPLATE_DOES_NOT_EXIST = "vc_template_does_not_exist";
    public static final String VC_DOES_NOT_EXIST = "vc_does_not_exist";
    public static final String USER_DOES_NOT_EXIST = "user_does_not_exist";
    public static final String OPERATION_NOT_SUPPORTED = "operation_not_supported";
    public static final String JWT_VERIFICATION_ERROR = "jwt_verification_error";
    public static final String RESPONSE_URI_ERROR = "response_uri_error";
    public static final String INSUFFICIENT_PERMISSION = "insufficient_permission";
    public static final String NOT_FOUND_RESOURCE = "not_found_resource";
    public static final String PARSING_CREDENTIAL_ERROR = "parsing_credential_error";
    public static final String BASE_45_ERROR = "base_45_error";
    public static final String CREATE_DATE_ERROR = "create_date_error";
    public static final String SIGNED_DATA_PARSING_ERROR = "signed_data_parsing_error";
    public static final String AUTHENTIC_SOURCES_USER_PARSING_ERROR = "authentic_sources_user_parsing_error";
    public static final String PARSE_CREDENTIAL_JSON_ERROR = "parse_credential_json_error";
    public static final String TEMPLATE_READ_ERROR = "template_read_error";
    public static final String PROOF_VALIDATION_ERROR = "proof_validation_error";
    public static final String CREDENTIAL_NOT_FOUND = "credential_not_found";
    public static final String PRE_AUTHORIZATION_CODE_GET_ERROR = "pre_authorization_code_get_error";
    public static final String CREDENTIAL_OFFER_NOT_FOUND = "credential_offer_not_found";
    public static final String CREDENTIAL_ALREADY_ISSUED = "credential_already_issued";
    public static final String EMAIL_COMMUNICATION_ERROR = "email_communication_error";
}
