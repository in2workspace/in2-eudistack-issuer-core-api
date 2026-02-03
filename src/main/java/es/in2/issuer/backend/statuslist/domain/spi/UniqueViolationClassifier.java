package es.in2.issuer.backend.statuslist.domain.spi;

public interface UniqueViolationClassifier {

    enum Kind {
        IDX,          // uq_status_list_index_list_id_idx
        PROCEDURE,    // uq_status_list_index_procedure_id
        UNKNOWN,      // unique violation but cannot map constraint
        NOT_UNIQUE
    }

    Kind classify(Throwable t);
}

