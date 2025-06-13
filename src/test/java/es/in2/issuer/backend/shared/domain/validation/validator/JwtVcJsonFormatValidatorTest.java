package es.in2.issuer.backend.shared.domain.validation.validator;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class JwtVcJsonFormatValidatorTest {

    @Mock
    private ConstraintValidatorContext constraintValidatorContext;

    @InjectMocks
    private JwtVcJsonFormatValidator jwtVcJsonFormatValidator;

    @Test
    void isValid_WithValidFormatValue_ReturnsTrue() {
        var result = jwtVcJsonFormatValidator.isValid(JWT_VC_JSON, constraintValidatorContext);

        assertThat(result).isTrue();
    }

    @Test
    void isValid_WithInvalidFormatValue_ReturnsFalse() {
        String invalidValue = "invalid_value";

        var result = jwtVcJsonFormatValidator.isValid(invalidValue, constraintValidatorContext);

        assertThat(result).isFalse();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isValid_WithNullOrEmptyValue_ReturnsFalse(String nullOrEmptyValue) {
        boolean isValid = jwtVcJsonFormatValidator.isValid(nullOrEmptyValue, constraintValidatorContext);

        assertThat(isValid).isFalse();
    }

    @Test
    void isValid_WithCaseInsensitiveMatch_ReturnsFalse() {
        String validValue = JWT_VC_JSON.toUpperCase();

        var result = jwtVcJsonFormatValidator.isValid(validValue, constraintValidatorContext);

        assertThat(result).isFalse();
    }
}