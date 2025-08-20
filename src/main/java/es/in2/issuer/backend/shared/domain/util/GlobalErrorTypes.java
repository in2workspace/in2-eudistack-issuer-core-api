package es.in2.issuer.backend.shared.domain.util;

public class GlobalErrorTypes {

    private GlobalErrorTypes() {
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
    public static final String RESPONSE_URI_ERROR = "response_uri_error";
    public static final String FORMAT_IS_NOT_SUPPORTED = "format_is_not_supported";
    public static final String INSUFFICIENT_PERMISSION = "insufficient_permission";
    public static final String MISSING_HEADER = "missing_header";
    public static final String SAD_ERROR = "sad_error";
    public static final String NO_SUCH_ELEMENT = "no_such_element";
    public static final String PARSE_ERROR = "parse_error";
    public static final String PROOF_VALIDATION_ERROR = "proof_validation_error";
    public static final String CREDENTIAL_NOT_FOUND = "credential_not_found";
    public static final String PRE_AUTHORIZATION_CODE_GET = "pre_authorization_code_get_error";
    public static final String CREDENTIAL_OFFER_NOT_FOUND = "credential_offer_not_found";
    public static final String CREDENTIAL_ALREADY_ISSUED = "credential_already_issued";
    public static final String JWT_VERIFICATION = "jwt_verification_error";
    public static final String UNAUTHORIZED_ROLE = "unauthorized_role";
    public static final String EMAIL_COMMUNICATION = "email_communication_error";
}
