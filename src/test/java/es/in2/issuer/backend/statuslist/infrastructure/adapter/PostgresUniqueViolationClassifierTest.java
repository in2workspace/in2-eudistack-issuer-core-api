package es.in2.issuer.backend.statuslist.infrastructure.adapter;


import es.in2.issuer.backend.statuslist.domain.spi.UniqueViolationClassifier;
import io.r2dbc.spi.R2dbcException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PostgresUniqueViolationClassifierTest {

    @InjectMocks
    private PostgresUniqueViolationClassifier classifier;

    @Mock
    private R2dbcException r2dbcException;

    @Test
    @DisplayName("Should return NOT_UNIQUE when exception is not R2dbcException")
    void shouldReturnNotUniqueWhenNotR2dbc() {
        Throwable t = new RuntimeException("Generic error");
        UniqueViolationClassifier.Kind result = classifier.classify(t);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.NOT_UNIQUE);
    }

    @Test
    @DisplayName("Should return NOT_UNIQUE when SQL state is not 23505")
    void shouldReturnNotUniqueWhenDifferentSqlState() {
        when(r2dbcException.getSqlState()).thenReturn("42P01"); // Undefined table
        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.NOT_UNIQUE);
    }

    @Test
    @DisplayName("Should return UNKNOWN when message is null")
    void shouldReturnUnknownWhenMessageIsNull() {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn(null);

        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.UNKNOWN);
    }

    @Test
    @DisplayName("Should return UNKNOWN when regex does not match")
    void shouldReturnUnknownWhenNoRegexMatch() {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn("Some other error without constraint info");

        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.UNKNOWN);
    }

    @Test
    @DisplayName("Should return IDX when constraint name matches")
    void shouldReturnIdx() {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn("duplicate key value violates unique constraint \"uq_status_list_index_list_id_idx\"");

        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.IDX);
    }

    @Test
    @DisplayName("Should return PROCEDURE when constraint name matches")
    void shouldReturnProcedure() {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn("violates unique constraint \"uq_status_list_index_procedure_id\"");

        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.PROCEDURE);
    }

    @Test
    @DisplayName("Should return UNKNOWN when constraint name is recognized but not mapped")
    void shouldReturnUnknownForUnmappedConstraint() {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn("unique constraint \"other_constraint_name\"");

        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.UNKNOWN);
    }

    @Test
    @DisplayName("Should find R2dbcException even if it is wrapped (nested cause)")
    void shouldFindCauseRecursively() {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn("unique constraint \"uq_status_list_index_procedure_id\"");

        // Embolcallem l'excepció en una RuntimeException
        Throwable wrapped = new RuntimeException("Outer", new RuntimeException("Middle", r2dbcException));

        UniqueViolationClassifier.Kind result = classifier.classify(wrapped);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.PROCEDURE);
    }
}