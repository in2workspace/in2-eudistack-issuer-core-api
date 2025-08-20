package es.in2.issuer.backend.backoffice.domain.util;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum BackofficeErrorTypes {

    NO_SUCH_ENTITY("no_such_entity"),
    TEMPLATE_READ_ERROR("template_read_error"),
    ORGANIZATION_ID_MISMATCH("organization_id_mismatch"),
    MISSING_REQUIRED_DATA("missing_required_data"),
    INVALID_SIGNATURE_CONFIGURATION("invalid_signature_configuration");

    private final String code;


}
