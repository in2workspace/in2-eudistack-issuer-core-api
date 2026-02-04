package es.in2.issuer.backend.statuslist.domain.spi;

public interface UniqueViolationClassifier {

    enum Kind {
        IDX,          // status list index
        PROCEDURE_ID,    // procedure id
        UNKNOWN,      // unique violation but cannot map constraint
        NOT_UNIQUE
    }

    Kind classify(Throwable t);
}

