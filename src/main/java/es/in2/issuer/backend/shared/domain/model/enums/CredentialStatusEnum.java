package es.in2.issuer.backend.shared.domain.model.enums;

public enum CredentialStatusEnum {
    WITHDRAWN, //fixme: Deprecated. Old status. Necessary to maintain retro compatibility.
    DRAFT,
    PEND_DOWNLOAD,
    PEND_SIGNATURE,
    ISSUED,
    VALID,
    REVOKED,
    EXPIRED
}
