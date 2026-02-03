package es.in2.issuer.backend.statuslist.domain.model;

public enum UniqueConstraintKind {
    IDX,          // uq_status_list_index_list_id_idx
    PROCEDURE,    // uq_status_list_index_procedure_id
    UNKNOWN,      // unique violation but constraint name not extracted / not matched
    NOT_UNIQUE    // not a unique violation (or not even SQLSTATE available)
}
