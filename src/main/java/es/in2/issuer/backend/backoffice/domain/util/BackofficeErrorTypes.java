package es.in2.issuer.backend.backoffice.domain.util;

public class BackofficeErrorTypes {

    private BackofficeErrorTypes() {
        throw new IllegalStateException("Utility class");
    }

    public static final String NO_SUCH_ENTITY = "no_such_entity";
    public static final String TEMPLATE_READ_ERROR = "template_read_error";
    public static final String ORGANIZATION_ID_MISMATCH = "organization_id_mismatch";
    public static final String MISSING_REQUIRED_DATA = "missing_required_data";
    public static final String INVALID_SIGNATURE_CONFIGURATION = "invalid_signature_configuration";
}
