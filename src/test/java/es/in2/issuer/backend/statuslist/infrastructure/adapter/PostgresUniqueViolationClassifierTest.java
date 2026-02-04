package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import es.in2.issuer.backend.statuslist.domain.spi.UniqueViolationClassifier;
import io.r2dbc.spi.R2dbcException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.Stream;

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
        when(r2dbcException.getSqlState()).thenReturn("42P01");
        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.NOT_UNIQUE);
    }

    @ParameterizedTest
    @MethodSource("provideUnknownCases")
    @DisplayName("Should return UNKNOWN for various error cases")
    void shouldReturnUnknownForVariousCases(String message, String description) {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn(message);

        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.UNKNOWN);
    }

    private static Stream<Arguments> provideUnknownCases() {
        return Stream.of(
                Arguments.of(null, "message is null"),
                Arguments.of("Some other error without constraint info", "regex does not match"),
                Arguments.of("unique constraint \"other_constraint_name\"", "constraint name is not mapped")
        );
    }

    @ParameterizedTest
    @MethodSource("provideConstraintMappings")
    @DisplayName("Should return correct Kind based on constraint name")
    void shouldReturnCorrectKindForConstraint(String message, UniqueViolationClassifier.Kind expectedKind) {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn(message);

        UniqueViolationClassifier.Kind result = classifier.classify(r2dbcException);
        assertThat(result).isEqualTo(expectedKind);
    }

    private static Stream<Arguments> provideConstraintMappings() {
        return Stream.of(
                Arguments.of(
                        "duplicate key value violates unique constraint \"uq_status_list_index_list_id_idx\"",
                        UniqueViolationClassifier.Kind.IDX
                ),
                Arguments.of(
                        "violates unique constraint \"uq_status_list_index_procedure_id\"",
                        UniqueViolationClassifier.Kind.PROCEDURE_ID
                )
        );
    }

    @Test
    @DisplayName("Should find R2dbcException even if it is wrapped (nested cause)")
    void shouldFindCauseRecursively() {
        when(r2dbcException.getSqlState()).thenReturn("23505");
        when(r2dbcException.getMessage()).thenReturn("unique constraint \"uq_status_list_index_procedure_id\"");

        Throwable wrapped = new RuntimeException("Outer", new RuntimeException("Middle", r2dbcException));

        UniqueViolationClassifier.Kind result = classifier.classify(wrapped);
        assertThat(result).isEqualTo(UniqueViolationClassifier.Kind.PROCEDURE_ID);
    }
}