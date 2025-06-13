package es.in2.issuer.backend.shared.domain.validation.validator;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SYNC;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class SyncOperationModeValidatorTest {

    @Mock
    private ConstraintValidatorContext constraintValidatorContext;

    @InjectMocks
    private SyncOperationModeValidator syncOperationModeValidator;

    @Test
    void isValid_WithValidOperationModeValue_ReturnsTrue() {
        var result = syncOperationModeValidator.isValid(SYNC, constraintValidatorContext);

        assertThat(result).isTrue();
    }

    @Test
    void isValid_WithInvalidOperationModeValue_ReturnsFalse() {
        String invalidValue = "invalid_value";

        var result = syncOperationModeValidator.isValid(invalidValue, constraintValidatorContext);

        assertThat(result).isFalse();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isValid_WithNullOrEmptyValue_ReturnsFalse(String nullOrEmptyValue) {
        boolean isValid = syncOperationModeValidator.isValid(nullOrEmptyValue, constraintValidatorContext);

        assertThat(isValid).isFalse();
    }

    @Test
    void isValid_WithCaseInsensitiveMatch_ReturnsFalse() {
        String validValue = SYNC.toLowerCase();

        var result = syncOperationModeValidator.isValid(validValue, constraintValidatorContext);

        assertThat(result).isFalse();
    }
}