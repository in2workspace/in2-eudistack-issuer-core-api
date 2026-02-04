package es.in2.issuer.backend.statuslist.infrastructure.adapter;
import es.in2.issuer.backend.statuslist.domain.spi.UniqueViolationClassifier;
import io.r2dbc.spi.R2dbcException;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class PostgresUniqueViolationClassifier implements UniqueViolationClassifier {

    private static final String SQLSTATE_UNIQUE_VIOLATION = "23505";

    private static final Pattern UNIQUE_CONSTRAINT = Pattern.compile("unique constraint \"([^\"]+)\"");

    @Override
    public Kind classify(Throwable t) {
        R2dbcException ex = findCause(t, R2dbcException.class);
        if (ex == null || !SQLSTATE_UNIQUE_VIOLATION.equals(ex.getSqlState())) {
            return Kind.NOT_UNIQUE;
        }

        String name = extractConstraintName(ex);
        if (name == null) {
            return Kind.UNKNOWN;
        }

        if ("uq_status_list_index_list_id_idx".equals(name)) {
            return Kind.IDX;
        }
        if ("uq_status_list_index_procedure_id".equals(name)) {
            return Kind.PROCEDURE_ID;
        }

        return Kind.UNKNOWN;
    }

    private String extractConstraintName(R2dbcException ex) {
        String msg = ex.getMessage();
        if (msg == null) {
            return null;
        }
        Matcher m = UNIQUE_CONSTRAINT.matcher(msg);
        return m.find() ? m.group(1) : null;
    }

    private <T extends Throwable> T findCause(Throwable t, Class<T> type) {
        Throwable cur = t;
        while (cur != null) {
            if (type.isInstance(cur)) {
                return type.cast(cur);
            }
            cur = cur.getCause();
        }
        return null;
    }
}
